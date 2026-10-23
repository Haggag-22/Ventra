#!/usr/bin/env python3
"""Smoke-test the console bundled in an installed ventra wheel (CI ``package`` job).

Starts ``ventra gui --no-open`` against a throwaway VENTRA_HOME, imports an evidence package
through the API, and checks that a case page is actually usable from the static export:

* ``/cases/<id>/cloudtrail/`` serves the page shell (HTML);
* ``/cases/<id>/cloudtrail/index.txt`` serves the RSC payload (text/plain) that Next fetches on
  client-side navigation — not the ``index.html`` fallback;
* with ``--browser``, headless Chromium loads the page and it requests ``/api/cases/<id>/...``,
  never ``/api/cases/_/...`` (the static-export placeholder leaking into API calls).

Usage:
    python scripts/smoke-packaged-console.py --ventra .venv/bin/ventra \\
        --package /tmp/demo/CASE-2026-0042.tar.zst --home /tmp/ventra-home [--browser]

Every check runs; the script exits non-zero after listing all the ones that failed.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def _free_port() -> int:
    """Return a TCP port on 127.0.0.1 that is free right now."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str) -> tuple[int, str, str]:
    """GET ``url``; return (status, content-type, body). HTTP errors are returned, not raised."""
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.status, resp.headers.get("content-type", ""), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("content-type", ""), exc.read().decode("utf-8", "replace")


def _wait_for_health(base: str, server: subprocess.Popen, timeout: float = 60) -> None:
    """Poll /api/health until it answers 200, the server exits, or ``timeout`` passes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise SystemExit(f"FAIL: ventra gui exited early with code {server.returncode}")
        try:
            if _get(f"{base}/api/health")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.5)
    raise SystemExit(f"FAIL: {base}/api/health did not come up within {timeout:.0f}s")


def _import_package(base: str, package: Path) -> str:
    """POST ``package`` to /api/cases/import as multipart field ``file``; return the case ID."""
    boundary = uuid.uuid4().hex
    body = (
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{package.name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + package.read_bytes()
        + f"\r\n--{boundary}--\r\n".encode()
    )
    req = urllib.request.Request(
        f"{base}/api/cases/import",
        data=body,
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            result = json.load(resp)
    except urllib.error.HTTPError as exc:
        raise SystemExit(
            f"FAIL: import returned {exc.code}: {exc.read().decode('utf-8', 'replace')}"
        ) from exc
    print(f"imported {result['case_id']}: {result['events']} events, integrity={result['integrity']}")
    return result["case_id"]


def _check_static_routes(base: str, case_id: str) -> list[str]:
    """The case page shell and its RSC payload must both resolve for a real case ID."""
    failures = []
    page = f"{base}/cases/{case_id}/cloudtrail/"
    status, ctype, body = _get(page)
    if status != 200 or "text/html" not in ctype or "<html" not in body.lower():
        failures.append(f"GET {page} -> {status} {ctype!r}, expected an HTML page")
    else:
        print(f"ok   GET {page} -> {status} {ctype}")

    rsc = f"{page}index.txt"
    status, ctype, body = _get(rsc)
    if status != 200 or not ctype.startswith("text/plain"):
        failures.append(
            f"GET {rsc} -> {status} {ctype!r}, expected the text/plain RSC payload "
            "(an HTML response means the SPA rewrite fell back to index.html)"
        )
    else:
        print(f"ok   GET {rsc} -> {status} {ctype}")
    return failures


def _check_in_browser(base: str, case_id: str) -> list[str]:
    """Load the case page in headless Chromium and check which case its API calls name."""
    from playwright.sync_api import sync_playwright

    api_paths: list[str] = []
    page_url = f"{base}/cases/{case_id}/cloudtrail/"
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        page.on(
            "request",
            lambda r: api_paths.append(r.url[len(base) :]) if r.url.startswith(f"{base}/api/") else None,
        )
        page.goto(page_url, wait_until="networkidle", timeout=60_000)
        browser.close()

    case_calls = [p for p in api_paths if p.startswith("/api/cases/")]
    print(f"browser made {len(api_paths)} API requests, {len(case_calls)} under /api/cases/")
    placeholder = [
        p for p in case_calls if p.startswith("/api/cases/_/") or p in ("/api/cases/_", "/api/cases/%5F")
    ]
    if placeholder:
        return [
            "the case page called the API with the static-export placeholder '_' instead of "
            f"{case_id!r}:\n    " + "\n    ".join(placeholder[:10])
        ]
    if not any(p.startswith(f"/api/cases/{case_id}/") or p == f"/api/cases/{case_id}" for p in case_calls):
        return [
            f"{page_url} never requested /api/cases/{case_id}/...; API requests seen:\n    "
            + "\n    ".join(api_paths[:20] or ["(none)"])
        ]
    print(f"ok   browser requested /api/cases/{case_id}/... and never /api/cases/_/...")
    return []


def main() -> int:
    """Run the smoke test; return 0 when every check passed, 1 otherwise."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ventra", required=True, help="Path to the installed `ventra` executable.")
    ap.add_argument("--package", required=True, type=Path, help="Sealed evidence package to import.")
    ap.add_argument("--home", required=True, type=Path, help="Throwaway VENTRA_HOME for the server.")
    ap.add_argument("--port", type=int, default=0, help="Backend port (default: a free one).")
    ap.add_argument("--browser", action="store_true", help="Also run the headless Playwright check.")
    args = ap.parse_args()

    port = args.port or _free_port()
    base = f"http://127.0.0.1:{port}"
    args.home.mkdir(parents=True, exist_ok=True)
    log_path = args.home / "gui.log"
    env = {**os.environ, "VENTRA_HOME": str(args.home)}
    with log_path.open("w") as log:
        server = subprocess.Popen(
            [args.ventra, "gui", "--no-open", "--backend-port", str(port)],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        failures: list[str] | None = None  # stays None if a step raised before the checks ran
        try:
            _wait_for_health(base, server)
            case_id = _import_package(base, args.package)
            failures = _check_static_routes(base, case_id)
            if args.browser:
                failures += _check_in_browser(base, case_id)
        finally:
            server.terminate()
            server.wait(timeout=10)
            if failures != []:
                sys.stdout.write(f"--- ventra gui output ---\n{log_path.read_text()}")
    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        return 1
    print("packaged console smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
