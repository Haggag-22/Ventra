"""Re-run Ventra under ``sudo`` when node-plane collection needs root.

Kubernetes node-plane collectors read the host filesystem directly (API-server audit logs,
``/var/log/pods``, the k3s/RKE2 agent directory). Those paths are root-only by design, so a
collection run as an ordinary user silently misses the most important evidence on the node.

Instead of making the operator retype ``sudo ~/.local/bin/ventra …``, the CLI re-executes
itself as ``sudo <this interpreter> -m collector <same arguments>``. sudo still asks for the
operator's password; nothing here bypasses authentication. After the run, files root created
are handed back to the invoking user, and custody records name the real operator.

Opt out with ``--no-sudo`` or ``VENTRA_NO_SUDO=1``.
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path

ELEVATED_ENV = "VENTRA_ELEVATED"
NO_SUDO_ENV = "VENTRA_NO_SUDO"

ENV_FILE_ENV = "VENTRA_ELEVATE_ENV_FILE"

# Environment the elevated run must see. sudo resets the environment, and root's HOME differs,
# so the invoking user's kubeconfig and Ventra settings are passed through explicitly — via a
# private 0600 file, never on the command line (argv is visible to every user in `ps`).
_PASSTHROUGH_PREFIXES = ("VENTRA_", "KUBECONFIG", "AWS_", "AZURE_", "GOOGLE_", "CLOUDSDK_")
_PASSTHROUGH_NAMES = ("NO_COLOR", "TERM", "COLUMNS", "LANG", "LC_ALL", "TZ")

_started_at = time.time()
_handback_roots: list[Path] = []


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def is_elevated_run() -> bool:
    """True when running as root via sudo (re-launched by Ventra, or `sudo ventra …` by hand)."""
    return is_root() and bool(os.environ.get("SUDO_UID"))


def invoking_user() -> str:
    """The human operator, even when running under sudo."""
    if is_root() and os.environ.get("SUDO_USER"):
        return os.environ["SUDO_USER"]
    try:
        import getpass

        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def _sudo_allowed_without_prompt(sudo: str) -> bool:
    try:
        return subprocess.run([sudo, "-n", "true"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _passthrough_env() -> dict[str, str]:
    env = {
        k: v for k, v in os.environ.items() if k.startswith(_PASSTHROUGH_PREFIXES) or k in _PASSTHROUGH_NAMES
    }
    if "KUBECONFIG" not in env:
        default = Path.home() / ".kube" / "config"
        if default.is_file():
            env["KUBECONFIG"] = str(default)
    env[ELEVATED_ENV] = "1"
    return env


def reexec_with_sudo(argv: Iterable[str], *, reason: str, disabled: bool = False) -> None:
    """Replace this process with ``sudo … -m collector <argv>`` if root is needed and possible.

    Returns (without elevating) when already root, on non-Linux hosts, when opted out, or when
    sudo can't be used; in the last case a warning explains what will be missed.
    """
    if is_root() or not sys.platform.startswith("linux"):
        return
    if disabled or os.environ.get(NO_SUDO_ENV, "").strip() in ("1", "true", "yes"):
        _warn_unprivileged(reason, "--no-sudo / VENTRA_NO_SUDO is set")
        return
    sudo = shutil.which("sudo")
    if sudo is None:
        _warn_unprivileged(reason, "sudo is not installed")
        return
    if not sys.stdin.isatty() and not _sudo_allowed_without_prompt(sudo):
        _warn_unprivileged(reason, "no terminal to prompt for the sudo password")
        return

    print(
        f"Ventra needs root to read {reason}.\n"
        "Re-running with sudo — you may be asked for your password. "
        "(Skip with --no-sudo; collection will then miss root-only evidence.)\n",
        file=sys.stderr,
        flush=True,
    )
    import json
    import tempfile

    fd, env_file = tempfile.mkstemp(prefix="ventra-elevate-", suffix=".json")  # created 0600
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(_passthrough_env(), fh)
    cmd = [sudo, "--", "env", f"{ENV_FILE_ENV}={env_file}", sys.executable, "-m", "collector", *argv]
    os.execv(sudo, cmd)


def load_passthrough_env() -> None:
    """In the elevated process: apply (then delete) the environment handed over by the caller."""
    path = os.environ.pop(ENV_FILE_ENV, "")
    if not path or not is_root():
        return
    import json

    try:
        env = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        env = {}
    finally:
        Path(path).unlink(missing_ok=True)
    for key, value in env.items():
        if isinstance(key, str) and isinstance(value, str):
            os.environ.setdefault(key, value)


def _warn_unprivileged(reason: str, why: str) -> None:
    print(
        f"warning: not running as root ({why}); {reason} will not be readable and those "
        "collectors will report gaps. Re-run with sudo to collect them.\n",
        file=sys.stderr,
        flush=True,
    )


def hand_back(*paths: Path | str | None) -> None:
    """After an elevated run, give files root created under ``paths`` back to the invoking user.

    Only entries owned by root and modified during this run are changed, so pointing ``--out``
    at an existing system directory can never re-own files that were already there.
    """
    if not is_elevated_run():
        return
    for p in paths:
        if p:
            _handback_roots.append(Path(p).expanduser().resolve())


def _chown_created(uid: int, gid: int) -> None:
    for root in _handback_roots:
        if not root.exists():
            continue
        entries = [root]
        if root.is_dir():
            entries.extend(root.rglob("*"))
        for entry in entries:
            try:
                st = entry.lstat()
                if st.st_uid == 0 and st.st_mtime >= _started_at - 1:
                    os.lchown(entry, uid, gid)
            except OSError:
                continue


@atexit.register
def _handback_at_exit() -> None:
    if not _handback_roots or not is_elevated_run():
        return
    try:
        _chown_created(int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID") or -1))
    except (KeyError, ValueError):
        return
