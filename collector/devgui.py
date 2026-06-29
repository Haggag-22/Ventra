"""Run the Ventra console GUI (``ventra gui``; ``ventra dev`` is an alias).

``ventra gui`` bootstraps everything on first run — venv, Python packages, and npm
dependencies — then starts the FastAPI backend with ``--reload`` and the Next.js dev server.
Save files and refresh the browser; no repackaging, no Docker. (A packaged desktop app is
planned for the v1 release; until then this is how you run and develop the GUI.)
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import webbrowser
from argparse import Namespace
from pathlib import Path

from collector.lib.uv_util import ensure_uv, uv_pip_install, uv_venv
from collector.lib.uv_util import venv_python as _venv_python_path

_SETUP_MARKER = ".ventra-dev-ready"
_NPM_MARKER = ".ventra-npm-ready"


def find_repo_root() -> Path:
    """Return the Ventra repo root, or exit with a helpful message."""
    env = os.environ.get("VENTRA_ROOT", "").strip()
    if env:
        root = Path(env).expanduser().resolve()
        if (root / "console/frontend/package.json").is_file():
            return root
        print(f"error: VENTRA_ROOT={root} is not a Ventra source tree.", file=sys.stderr)
        raise SystemExit(1)

    marker = Path("console/frontend/package.json")
    here = Path(__file__).resolve().parent
    for candidate in (Path.cwd(), here, *here.parents):
        if (candidate / marker).is_file():
            return candidate.resolve()

    print(
        "error: ventra dev/gui needs the Ventra source tree (console/frontend).\n"
        "  Clone the repo and run from its root, or set VENTRA_ROOT.",
        file=sys.stderr,
    )
    raise SystemExit(1)


def _find_python311() -> str:
    for cmd in ("python3.12", "python3.11", "python3"):
        if shutil.which(cmd) is None:
            continue
        probe = subprocess.run(
            [cmd, "-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"],
            capture_output=True,
        )
        if probe.returncode == 0:
            return cmd
    print("error: Python 3.11 or newer is required for ventra dev.", file=sys.stderr)
    raise SystemExit(1)


def _is_stale(marker: Path, *sources: Path) -> bool:
    if not marker.is_file():
        return True
    baseline = marker.stat().st_mtime
    return any(src.is_file() and src.stat().st_mtime > baseline for src in sources)


def _venv_ready(python: Path) -> bool:
    if not python.is_file():
        return False
    return (
        subprocess.run(
            [str(python), "-c", "import uvicorn, ventra_ingester, fastapi"],
            capture_output=True,
        ).returncode
        == 0
    )


def _create_venv(venv_dir: Path) -> Path:
    """Create a fresh ``.venv`` with uv."""
    py = _find_python311()
    uv = ensure_uv()
    if venv_dir.is_dir():
        shutil.rmtree(venv_dir)
    print(f"Creating Ventra dev virtualenv (.venv) with {py}…")
    return uv_venv(uv, venv_dir, python=py)


def ensure_dev_environment(root: Path, *, force: bool = False) -> Path:
    """Create ``.venv``, install Python + npm deps. Returns the venv Python executable."""
    uv = ensure_uv()
    venv_dir = root / ".venv"
    py_exec = _venv_python_path(venv_dir)
    setup_marker = venv_dir / _SETUP_MARKER

    pyproject_files = (
        root / "pyproject.toml",
        root / "ingester/pyproject.toml",
        root / "console/backend/pyproject.toml",
    )

    if force or not _venv_ready(py_exec):
        if venv_dir.is_dir() and not force:
            print("Repairing broken Ventra dev virtualenv (.venv)…")
        py_exec = _create_venv(venv_dir)

    if force or _is_stale(setup_marker, *pyproject_files):
        print("Installing Python dependencies (collector, ingester, console backend)…")
        uv_pip_install(
            uv,
            py_exec,
            "-e",
            f"{root}[dev]",
            "-e",
            f"{root / 'ingester'}[dev]",
            "-e",
            str(root / "console/backend"),
            quiet=False,
        )
        setup_marker.touch()

    frontend_dir = root / "console/frontend"
    lockfile = frontend_dir / "package-lock.json"
    npm_marker = venv_dir / _NPM_MARKER

    if shutil.which("npm") is None:
        print("error: npm is required for the Ventra console frontend.", file=sys.stderr)
        raise SystemExit(1)

    npm_stale = force or not (frontend_dir / "node_modules").is_dir()
    if lockfile.is_file():
        npm_stale = npm_stale or _is_stale(npm_marker, lockfile)
    elif not (frontend_dir / "node_modules").is_dir():
        npm_stale = True

    if npm_stale:
        print("Installing frontend dependencies (npm)…")
        subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund"],
            cwd=frontend_dir,
            check=True,
        )
        npm_marker.touch()

    (root / "cases").mkdir(parents=True, exist_ok=True)
    (root / ".ventra-uploads").mkdir(parents=True, exist_ok=True)

    return py_exec


def _port_available(port: int, *, bind_host: str = "127.0.0.1") -> bool:
    """Return True if ``bind_host:port`` can be bound (matches uvicorn / Next.js)."""
    if bind_host == "::":
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("::", port))
                return True
        except OSError:
            return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host, port))
            return True
    except OSError:
        return False


def _pick_port(preferred: int, *, bind_host: str = "127.0.0.1", max_tries: int = 10) -> int:
    for offset in range(max_tries):
        port = preferred + offset
        if _port_available(port, bind_host=bind_host):
            return port
    return preferred


def _wait_for_http(url: str, *, timeout: float = 90.0) -> bool:
    """Poll until an HTTP server responds or timeout."""
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status < 500:
                    return True
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.5)
    return False


def _dev_env(root: Path, venv_bin: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["VENTRA_CASE_STORE"] = str(root / "cases")
    env["VENTRA_UPLOAD_DIR"] = str(root / ".ventra-uploads")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PATH"] = f"{venv_bin}{os.pathsep}{env.get('PATH', '')}"
    return env


def _terminate(procs: list[subprocess.Popen[bytes]]) -> None:
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
    deadline = time.monotonic() + 5
    for proc in procs:
        if proc.poll() is not None:
            continue
        remaining = max(0, deadline - time.monotonic())
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            proc.kill()


def _wait_procs(procs: list[subprocess.Popen[bytes]]) -> int:
    try:
        while True:
            for proc in procs:
                code = proc.poll()
                if code is not None:
                    _terminate(procs)
                    return code
            time.sleep(0.25)
    except KeyboardInterrupt:
        _terminate(procs)
        return 130


def _verify_python_deps(python: Path) -> None:
    for module in ("uvicorn", "ventra_ingester", "fastapi"):
        probe = subprocess.run(
            [str(python), "-c", f"import {module}"],
            capture_output=True,
        )
        if probe.returncode != 0:
            print(f"error: {module} failed to import after setup.", file=sys.stderr)
            raise SystemExit(1)


def cmd_dev(args: Namespace) -> int:
    """Bootstrap if needed, then run hot-reload dev stack."""
    root = find_repo_root()
    backend_dir = root / "console/backend"
    frontend_dir = root / "console/frontend"

    venv_python = ensure_dev_environment(root, force=args.setup)
    _verify_python_deps(venv_python)
    venv_bin = venv_python.parent

    env = _dev_env(root, venv_bin)
    frontend_port = _pick_port(args.port, bind_host="::")
    backend_port = _pick_port(args.backend_port, bind_host="127.0.0.1")
    env["PORT"] = str(frontend_port)
    env["VENTRA_API"] = f"http://127.0.0.1:{backend_port}"

    procs: list[subprocess.Popen[bytes]] = []

    def on_signal(signum: int, _frame: object) -> None:
        _terminate(procs)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    print()
    print("Ventra console — save files, refresh the browser to see changes.")
    print(f"  Console (hot reload):  http://127.0.0.1:{frontend_port}")
    print(f"  Backend  (--reload):     http://127.0.0.1:{backend_port}")
    print(f"  Cases:                   {env['VENTRA_CASE_STORE']}")
    if frontend_port != args.port:
        print(f"  Note: port {args.port} busy — using {frontend_port}")
    if backend_port != args.backend_port:
        print(f"  Note: port {args.backend_port} busy — using {backend_port}")
    print()

    procs.append(
        subprocess.Popen(
            [
                str(venv_python),
                "-m",
                "uvicorn",
                "app.main:app",
                "--reload",
                "--host",
                "127.0.0.1",
                f"--port={backend_port}",
            ],
            cwd=backend_dir,
            env=env,
        )
    )
    time.sleep(1.5)
    backend_proc = procs[0]
    if backend_proc.poll() is not None:
        print(
            f"error: backend failed to start on port {backend_port}.\n"
            f"  Free the port: lsof -ti :{backend_port} | xargs kill -9\n"
            "  Then run ventra dev again.",
            file=sys.stderr,
        )
        _terminate(procs)
        return 1

    _repair_next_dev_build(frontend_dir, force=args.setup)

    procs.append(
        subprocess.Popen(
            ["npm", "run", "dev"],
            cwd=frontend_dir,
            env=env,
        )
    )

    if not args.no_open:
        print("Waiting for backend and frontend…")
        backend_ok = _wait_for_http(f"http://127.0.0.1:{backend_port}/api/health", timeout=30)
        frontend_ok = _wait_for_http(f"http://127.0.0.1:{frontend_port}", timeout=90)
        if not backend_ok:
            print(
                f"error: backend API not responding on port {backend_port}.",
                file=sys.stderr,
            )
        if frontend_ok:
            webbrowser.open(f"http://127.0.0.1:{frontend_port}")
        else:
            print(
                f"error: frontend did not start on port {frontend_port}. Check the logs above.",
                file=sys.stderr,
            )

    return _wait_procs(procs)


def _repair_next_dev_build(frontend_dir: Path, *, force: bool = False) -> None:
    """Refresh Next.js dev output so client chunks match the dev server."""
    next_dir = frontend_dir / ".next"
    if force and next_dir.is_dir():
        print("Clearing Next.js dev build (.next)…")
        shutil.rmtree(next_dir, ignore_errors=True)
        return
    if not next_dir.is_dir():
        return
    webpack_cache = next_dir / "cache" / "webpack"
    if webpack_cache.is_dir():
        shutil.rmtree(webpack_cache, ignore_errors=True)
    server = next_dir / "server"
    static = next_dir / "static"
    if server.is_dir() and not static.is_dir():
        print("Repairing stale Next.js dev build (.next)…")
        shutil.rmtree(next_dir, ignore_errors=True)


def cmd_gui(args: Namespace) -> int:
    """Open the Ventra console GUI (hot reload). Alias: ``ventra dev``."""
    return cmd_dev(args)
