"""Local console development (``ventra dev``) and production GUI (``ventra gui``).

``ventra dev`` bootstraps everything on first run — venv, Python packages, and npm
dependencies — then starts the FastAPI backend with ``--reload`` and the Next.js dev
server. Save files and refresh the browser; no repackaging.

``ventra gui`` runs the production stack (Docker Compose by default, or a local build with
``next start`` when ``--local`` is passed).
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


def ensure_dev_environment(root: Path, *, force: bool = False) -> Path:
    """Create ``.venv``, install Python + npm deps. Returns the venv Python executable."""
    venv_dir = root / ".venv"
    venv_python = venv_dir / "bin" / "python"
    pip = venv_dir / "bin" / "pip"
    setup_marker = venv_dir / _SETUP_MARKER

    pyproject_files = (
        root / "pyproject.toml",
        root / "ingester/pyproject.toml",
        root / "console/backend/pyproject.toml",
    )

    if not venv_python.is_file():
        print("Creating Ventra dev virtualenv (.venv)…")
        subprocess.run([_find_python311(), "-m", "venv", str(venv_dir)], check=True)

    if force or _is_stale(setup_marker, *pyproject_files):
        print("Installing Python dependencies (collector, ingester, console backend)…")
        subprocess.run([str(pip), "install", "--upgrade", "pip"], check=True)
        subprocess.run(
            [
                str(pip),
                "install",
                "-e",
                f"{root}[dev]",
                "-e",
                f"{root / 'ingester'}[dev]",
                "-e",
                f"{root / 'console/backend'}",
            ],
            check=True,
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

    return venv_python


def _pick_port(host: str, preferred: int) -> int:
    for port in (preferred, preferred + 1, preferred + 2):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                continue
    return preferred


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
    frontend_port = _pick_port("127.0.0.1", args.port)
    backend_port = _pick_port("127.0.0.1", args.backend_port)

    procs: list[subprocess.Popen[bytes]] = []

    def on_signal(signum: int, _frame: object) -> None:
        _terminate(procs)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    print()
    print("Ventra dev — save files, refresh the browser to see changes.")
    print(f"  Frontend (hot reload): http://127.0.0.1:{frontend_port}")
    print(f"  Backend  (--reload):     http://127.0.0.1:{backend_port}")
    print(f"  Cases:                   {env['VENTRA_CASE_STORE']}")
    if frontend_port != args.port:
        print(f"  Note: port {args.port} busy — using {frontend_port}")
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
    time.sleep(1)

    procs.append(
        subprocess.Popen(
            ["npm", "run", "dev", "--", "-p", str(frontend_port)],
            cwd=frontend_dir,
            env=env,
        )
    )

    if not args.no_open:
        time.sleep(2)
        webbrowser.open(f"http://127.0.0.1:{frontend_port}")

    return _wait_procs(procs)


def cmd_gui(args: Namespace) -> int:
    """Production GUI — Docker Compose by default, or a local build with ``--local``."""
    root = find_repo_root()
    compose = root / "deploy/compose/ventra.yml"

    if not args.local and shutil.which("docker") and compose.is_file():
        print("Ventra gui — production stack (Docker Compose).")
        print("  Console: http://127.0.0.1:8080")
        print("  Stop with Ctrl+C or: docker compose -f deploy/compose/ventra.yml down")
        print()
        if not args.no_open:
            time.sleep(3)
            webbrowser.open("http://127.0.0.1:8080")
        return subprocess.call(
            ["docker", "compose", "-f", str(compose), "up", "--build"],
            cwd=root,
        )

    if not args.local:
        print(
            "Docker not available — falling back to local production mode.\n"
            "  Pass --local explicitly to skip this message next time.",
            file=sys.stderr,
        )

    return _gui_local(root, args)


def _gui_local(root: Path, args: Namespace) -> int:
    backend_dir = root / "console/backend"
    frontend_dir = root / "console/frontend"

    venv_python = ensure_dev_environment(root, force=args.setup or args.rebuild)
    _verify_python_deps(venv_python)
    venv_bin = venv_python.parent

    env = _dev_env(root, venv_bin)
    frontend_port = _pick_port("127.0.0.1", args.port)
    backend_port = _pick_port("127.0.0.1", args.backend_port)

    if args.rebuild or not (frontend_dir / ".next").is_dir():
        print("Building frontend…")
        subprocess.run(["npm", "run", "build"], cwd=frontend_dir, env=env, check=True)

    procs: list[subprocess.Popen[bytes]] = []

    def on_signal(signum: int, _frame: object) -> None:
        _terminate(procs)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    print("Ventra gui — local production (no hot reload).")
    print(f"  Frontend: http://127.0.0.1:{frontend_port}")
    print(f"  Backend:  http://127.0.0.1:{backend_port}")
    print()

    procs.append(
        subprocess.Popen(
            [
                str(venv_python),
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                f"--port={backend_port}",
            ],
            cwd=backend_dir,
            env=env,
        )
    )
    time.sleep(1)

    procs.append(
        subprocess.Popen(
            ["npm", "run", "start", "--", "-p", str(frontend_port)],
            cwd=frontend_dir,
            env=env,
        )
    )

    if not args.no_open:
        time.sleep(2)
        webbrowser.open(f"http://127.0.0.1:{frontend_port}")

    return _wait_procs(procs)
