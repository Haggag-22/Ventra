"""Google Cloud client factory — ADC auth, project discovery, logging, SCC, IAM."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterator

from google.api_core import exceptions as gcp_exc
from google.auth import default as google_auth_default
from google.cloud import logging_v2
from google.cloud import resourcemanager_v3
from google.cloud import securitycenter_v1 as scc_v1


class GcpAccessDenied(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class GcpServiceNotEnabled(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


@dataclass
class GcpIdentity:
    project_id: str
    principal: str
    organization_id: str = ""
    organization_name: str = ""


def _entry_to_dict(entry: logging_v2.LogEntry) -> dict[str, Any]:
    payload = entry.payload
    if hasattr(payload, "items"):
        payload = dict(payload)
    elif payload is not None and not isinstance(payload, (dict, list, str, int, float, bool)):
        payload = str(payload)
    out: dict[str, Any] = {
        "logName": entry.log_name,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else "",
        "severity": entry.severity.name if entry.severity else "",
        "insertId": entry.insert_id,
        "resource": {
            "type": entry.resource.type if entry.resource else "",
            "labels": dict(entry.resource.labels) if entry.resource else {},
        },
        "labels": dict(entry.labels),
        "payload": payload,
    }
    if entry.proto_payload:
        try:
            from google.protobuf.json_format import MessageToDict

            out["protoPayload"] = MessageToDict(entry.proto_payload)
        except Exception:
            out["protoPayload"] = str(entry.proto_payload)
    if entry.text_payload:
        out["textPayload"] = entry.text_payload
    if entry.json_payload:
        out["jsonPayload"] = dict(entry.json_payload)
    return out


class GcpClientFactory:
    """Thin wrapper around Google Cloud SDK clients with typed gap exceptions."""

    def __init__(
        self,
        *,
        project_id: str | None = None,
        credentials_path: str | None = None,
    ) -> None:
        scopes = [
            "https://www.googleapis.com/auth/cloud-platform.read-only",
            "https://www.googleapis.com/auth/logging.read",
        ]
        if credentials_path:
            from google.oauth2 import service_account

            creds = service_account.Credentials.from_service_account_file(
                credentials_path, scopes=scopes
            )
            self._credentials = creds
            self._default_project = project_id or creds.project_id or ""
        else:
            self._credentials, self._default_project = google_auth_default(scopes=scopes)
            if project_id:
                self._default_project = project_id

        self._logging_clients: dict[str, logging_v2.Client] = {}
        self._rm = resourcemanager_v3.ProjectsClient(credentials=self._credentials)
        self._scc = scc_v1.SecurityCenterClient(credentials=self._credentials)

    def _logging_client(self, project_id: str) -> logging_v2.Client:
        if project_id not in self._logging_clients:
            self._logging_clients[project_id] = logging_v2.Client(
                project=project_id, credentials=self._credentials
            )
        return self._logging_clients[project_id]

    def caller_identity(self) -> GcpIdentity:
        principal = "unknown"
        if self._credentials:
            if hasattr(self._credentials, "service_account_email"):
                principal = self._credentials.service_account_email or principal
            elif hasattr(self._credentials, "signer_email"):
                principal = self._credentials.signer_email or principal
        project = self._default_project or ""
        org_id = ""
        org_name = ""
        if project:
            try:
                proj = self._rm.get_project(name=f"projects/{project}")
                parent = proj.parent or ""
                if parent.startswith("organizations/"):
                    org_id = parent.split("/", 1)[1]
            except gcp_exc.PermissionDenied as exc:
                raise GcpAccessDenied(str(exc)) from exc
            except gcp_exc.NotFound:
                pass
        return GcpIdentity(
            project_id=project,
            principal=principal,
            organization_id=org_id,
            organization_name=org_name,
        )

    def projects(self, *, explicit: list[str] | None = None) -> list[str]:
        if explicit:
            return explicit
        if self._default_project:
            return [self._default_project]
        ids: list[str] = []
        try:
            for proj in self._rm.search_projects(query="state:ACTIVE"):
                pid = proj.project_id
                if pid:
                    ids.append(pid)
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        except gcp_exc.GoogleAPIError as exc:
            raise GcpServiceNotEnabled(str(exc)) from exc
        return sorted(set(ids))

    def project_details(self, project_ids: list[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for pid in project_ids:
            try:
                proj = self._rm.get_project(name=f"projects/{pid}")
                out.append(
                    {
                        "project_id": proj.project_id,
                        "name": proj.display_name,
                        "state": proj.state.name if proj.state else "",
                        "parent": proj.parent,
                        "create_time": proj.create_time.isoformat() if proj.create_time else "",
                    }
                )
            except gcp_exc.PermissionDenied:
                out.append({"project_id": pid, "error": "access_denied"})
            except gcp_exc.NotFound:
                out.append({"project_id": pid, "error": "not_found"})
        return out

    def list_log_entries(
        self,
        project_id: str,
        *,
        log_filter: str,
        start: datetime,
        end: datetime,
        max_records: int,
    ) -> Iterator[dict[str, Any]]:
        client = self._logging_client(project_id)
        ts_start = start.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        ts_end = end.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        time_clause = f'timestamp >= "{ts_start}" AND timestamp <= "{ts_end}"'
        full_filter = f"({log_filter}) AND {time_clause}" if log_filter else time_clause
        try:
            count = 0
            for entry in client.list_entries(filter_=full_filter, order_by="timestamp desc"):
                yield _entry_to_dict(entry)
                count += 1
                if count >= max_records:
                    break
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        except gcp_exc.NotFound as exc:
            raise GcpServiceNotEnabled(str(exc)) from exc
        except gcp_exc.GoogleAPIError as exc:
            if "not enabled" in str(exc).lower() or "api has not been used" in str(exc).lower():
                raise GcpServiceNotEnabled(str(exc)) from exc
            raise

    def scc_findings(
        self,
        *,
        organization_id: str,
        max_records: int,
    ) -> Iterator[dict[str, Any]]:
        if not organization_id:
            return
        parent = f"organizations/{organization_id}"
        try:
            count = 0
            for finding in self._scc.list_findings(request={"parent": f"{parent}/sources/-"}):
                f = finding.finding
                if not f:
                    continue
                try:
                    from google.protobuf.json_format import MessageToDict

                    yield MessageToDict(f._pb)  # type: ignore[attr-defined]
                except Exception:
                    yield {"name": f.name, "category": f.category, "severity": f.severity.name}
                count += 1
                if count >= max_records:
                    break
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        except gcp_exc.NotFound as exc:
            raise GcpServiceNotEnabled(str(exc)) from exc

    def iam_policy_snapshot(self, project_id: str) -> dict[str, Any]:
        try:
            policy = self._rm.get_iam_policy(request={"resource": f"projects/{project_id}"})
            return {
                "project_id": project_id,
                "bindings": [
                    {"role": b.role, "members": list(b.members)} for b in policy.bindings
                ],
                "etag": policy.etag,
            }
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
