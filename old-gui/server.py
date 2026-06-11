"""Local read-only HTTP server for the evidence viewer.

Stdlib only (http.server) so investigators need zero extra dependencies.
Binds to 127.0.0.1 and serves the static frontend plus a small JSON API
over the opened evidence package.
"""

import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .state import PackageNotLoadedError, ViewerState
from .upload import load_from_upload

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
}


def make_handler(state):
    """Build a request handler bound to one ViewerState."""

    class ViewerHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # quiet default access logs
            pass

        # ------------------------------------------------------- responses

        def _send_json(self, payload, status=200):
            body = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_static(self, relative):
            relative = relative.lstrip("/") or "index.html"
            full = os.path.abspath(os.path.join(STATIC_DIR, relative))
            if not full.startswith(STATIC_DIR + os.sep) and full != os.path.join(
                    STATIC_DIR, relative):
                self._send_json({"error": "forbidden"}, 403)
                return
            if not os.path.isfile(full):
                self._send_json({"error": "not found"}, 404)
                return
            with open(full, "rb") as handle:
                body = handle.read()
            extension = os.path.splitext(full)[1]
            self.send_response(200)
            self.send_header("Content-Type",
                             CONTENT_TYPES.get(extension, "application/octet-stream"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _package(self):
            return state.get()

        # ------------------------------------------------------------ routes

        def do_GET(self):  # noqa: N802 - http.server naming
            parsed = urllib.parse.urlparse(self.path)
            route = parsed.path
            params = {key: values[0] for key, values
                      in urllib.parse.parse_qs(parsed.query).items()}
            try:
                if route == "/" or route == "/index.html":
                    self._send_static("index.html")
                elif route.startswith("/static/"):
                    self._send_static(route[len("/static/"):])
                elif route == "/api/status":
                    self._send_json(state.status())
                elif route == "/api/summary":
                    self._send_json(self._summary())
                elif route == "/api/coverage":
                    self._send_json(self._package().manifest.get("collectors", []))
                elif route == "/api/cloudtrail/facets":
                    self._send_json(self._package().cloudtrail_facets())
                elif route == "/api/cloudtrail":
                    self._send_json(self._cloudtrail(params))
                elif route.startswith("/api/cloudtrail/"):
                    idx = int(route.rsplit("/", 1)[1])
                    package = self._package()
                    raw = package.cloudtrail_event(idx)
                    self._send_json(raw if raw is not None
                                    else {"error": "not found"},
                                    200 if raw is not None else 404)
                elif route == "/api/findings":
                    self._send_json(self._package().query_findings(
                        search=params.get("search", ""),
                        source=params.get("source", ""),
                        severity=params.get("severity", ""),
                        limit=int(params.get("limit", 200)),
                        offset=int(params.get("offset", 0)),
                    ))
                elif route.startswith("/api/findings/"):
                    idx = int(route.rsplit("/", 1)[1])
                    package = self._package()
                    raw = package.finding(idx)
                    self._send_json(raw if raw is not None
                                    else {"error": "not found"},
                                    200 if raw is not None else 404)
                elif route == "/api/iam":
                    self._send_json(self._package().iam_summary())
                elif route == "/api/workload":
                    self._send_json(self._package().workload_summary())
                elif route == "/api/application":
                    self._send_json(self._package().application_summary())
                elif route == "/api/idp":
                    self._send_json(self._package().idp_summary())
                elif route == "/api/files":
                    self._send_json({"files": self._package().list_files()})
                elif route == "/api/file":
                    path = params.get("path", "")
                    self._send_json(self._package().read_file_for_view(path))
                else:
                    self._send_json({"error": "not found"}, 404)
            except PackageNotLoadedError:
                self._send_json({"error": "no package loaded"}, 503)
            except PermissionError:
                self._send_json({"error": "forbidden"}, 403)
            except FileNotFoundError:
                self._send_json({"error": "not found"}, 404)
            except Exception as exc:  # noqa: BLE001 - viewer must not crash
                self._send_json({"error": str(exc)}, 500)

        def do_POST(self):  # noqa: N802 - http.server naming
            parsed = urllib.parse.urlparse(self.path)
            try:
                if parsed.path == "/api/upload":
                    result = load_from_upload(self, state)
                    self._send_json(result)
                else:
                    self._send_json({"error": "not found"}, 404)
            except (ValueError, PermissionError) as exc:
                self._send_json({"error": str(exc)}, 400)
            except FileNotFoundError as exc:
                self._send_json({"error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001 - viewer must not crash
                self._send_json({"error": str(exc)}, 500)

        # ------------------------------------------------------------ views

        def _summary(self):
            package = self._package()
            manifest = package.manifest
            by_status = {}
            issues = []
            for entry in manifest.get("collectors", []):
                for result in entry.get("results", []):
                    status = result.get("status", "unknown")
                    by_status[status] = by_status.get(status, 0) + 1
                    if status in ("permission_denied", "failed"):
                        issues.append({
                            "collector": entry.get("name"),
                            "region": result.get("region"),
                            "status": status,
                            "detail": result.get("detail", ""),
                        })
            workload = package.workload_summary()
            idp = package.idp_summary()
            cloudtrail_data = package.cloudtrail_data_coverage()
            return {
                "tool": manifest.get("tool", {}),
                "scope": manifest.get("scope", {}),
                "run": manifest.get("run", {}),
                "stats": {
                    "files": len(manifest.get("files", [])),
                    "collectors": len(manifest.get("collectors", [])),
                    "events_indexed": len(package.cloudtrail_index),
                    "findings": len(package.findings_index),
                    "ec2_instances": len(workload.get("ec2_instances", [])),
                    "shared_snapshots": len(workload.get("shared_snapshots", [])),
                    "idp_events": idp.get("total_events", 0),
                    "s3_data_events_collected": cloudtrail_data.get(
                        "s3_data_events_collected", 0),
                    "by_status": by_status,
                },
                "cloudtrail_data": cloudtrail_data,
                "issues": issues,
            }

        def _cloudtrail(self, params):
            names = _csv_param(params.get("events"))
            sources = _csv_param(params.get("sources"))
            regions = _csv_param(params.get("regions"))
            return self._package().query_cloudtrail(
                search=params.get("search", ""),
                names=names,
                sources=sources,
                regions=regions,
                user=params.get("user", ""),
                ip=params.get("ip", ""),
                errors_only=params.get("errors") == "1",
                sort=params.get("sort", "time"),
                order=params.get("order", "desc"),
                limit=int(params.get("limit", 100)),
                offset=int(params.get("offset", 0)),
            )

    return ViewerHandler


def _csv_param(value):
    if not value:
        return None
    items = [item.strip() for item in value.split(",") if item.strip()]
    return items or None


def serve(state, host="127.0.0.1", port=8400):
    server = ThreadingHTTPServer((host, port), make_handler(state))
    server.state = state
    return server
