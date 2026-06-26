"""Google Cloud client factory — ADC auth, project discovery, logging, SCC, IAM, Compute."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Iterator

from google.api_core import exceptions as gcp_exc
from google.auth import default as google_auth_default
from google.cloud import compute_v1
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
        self._compute: dict[str, Any] = {}
        self._iam: Any = None

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

    def _iam_client(self) -> Any:
        if self._iam is None:
            from google.cloud import iam_admin_v1

            self._iam = iam_admin_v1.IAMClient(credentials=self._credentials)
        return self._iam

    @staticmethod
    def _iam_etag(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value or "")

    @staticmethod
    def _iam_policy_dict(policy: Any) -> dict[str, Any]:
        bindings: list[dict[str, Any]] = []
        for binding in policy.bindings:
            row: dict[str, Any] = {"role": binding.role, "members": list(binding.members)}
            if binding.condition and binding.condition.expression:
                row["condition"] = GcpClientFactory._proto_to_dict(binding.condition)
            bindings.append(row)
        return {
            "bindings": bindings,
            "etag": GcpClientFactory._iam_etag(policy.etag),
        }

    def iam_policy_snapshot(self, project_id: str) -> dict[str, Any]:
        try:
            policy = self._rm.get_iam_policy(request={"resource": f"projects/{project_id}"})
            out = self._iam_policy_dict(policy)
            out["project_id"] = project_id
            return out
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc

    def list_service_accounts(
        self, project_id: str, *, max_items: int = 500
    ) -> list[dict[str, Any]]:
        client = self._iam_client()
        out: list[dict[str, Any]] = []
        try:
            for sa in client.list_service_accounts(request={"name": f"projects/{project_id}"}):
                out.append(self._proto_to_dict(sa))
                if len(out) >= max_items:
                    return out
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        return out

    def list_service_account_keys(self, service_account_name: str) -> list[dict[str, Any]]:
        client = self._iam_client()
        try:
            response = client.list_service_account_keys(request={"name": service_account_name})
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        keys: list[dict[str, Any]] = []
        for key in response.keys:
            keys.append(
                {
                    "name": key.name,
                    "keyAlgorithm": key.key_algorithm.name if key.key_algorithm else "",
                    "keyOrigin": key.key_origin.name if key.key_origin else "",
                    "keyType": key.key_type.name if key.key_type else "",
                    "validAfterTime": key.valid_after_time.isoformat()
                    if key.valid_after_time
                    else "",
                    "validBeforeTime": key.valid_before_time.isoformat()
                    if key.valid_before_time
                    else "",
                    "disabled": key.disabled,
                }
            )
        return keys

    def service_account_iam_policy(self, service_account_name: str) -> dict[str, Any]:
        client = self._iam_client()
        try:
            policy = client.get_iam_policy(request={"resource": service_account_name})
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        return self._iam_policy_dict(policy)

    def list_project_custom_roles(
        self, project_id: str, *, max_items: int = 200
    ) -> list[dict[str, Any]]:
        client = self._iam_client()
        out: list[dict[str, Any]] = []
        try:
            for role in client.list_roles(request={"parent": f"projects/{project_id}"}):
                out.append(self._proto_to_dict(role))
                if len(out) >= max_items:
                    return out
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        return out

    # -- Compute Engine (read-only inventory / posture) -----------------------------------

    def _compute_client(self, name: str, factory: Callable[..., Any]) -> Any:
        if name not in self._compute:
            self._compute[name] = factory(credentials=self._credentials)
        return self._compute[name]

    @staticmethod
    def _proto_to_dict(msg: Any) -> dict[str, Any]:
        if msg is None:
            return {}
        try:
            from google.protobuf.json_format import MessageToDict

            return MessageToDict(msg, preserving_proto_field_name=True)
        except Exception:
            return {"_raw": str(msg)}

    def _raise_compute(self, exc: Exception) -> None:
        if isinstance(exc, gcp_exc.PermissionDenied):
            raise GcpAccessDenied(str(exc)) from exc
        if isinstance(exc, gcp_exc.NotFound):
            raise GcpServiceNotEnabled(str(exc)) from exc
        msg = str(exc).lower()
        if "not enabled" in msg or "api has not been used" in msg or "service disabled" in msg:
            raise GcpServiceNotEnabled(str(exc)) from exc
        raise exc

    def _list_compute(
        self,
        *,
        client_name: str,
        client_factory: Callable[..., Any],
        list_method: str,
        request: Any,
        max_items: int,
    ) -> list[dict[str, Any]]:
        client = self._compute_client(client_name, client_factory)
        out: list[dict[str, Any]] = []
        try:
            for item in getattr(client, list_method)(request=request):
                out.append(self._proto_to_dict(item))
                if len(out) >= max_items:
                    return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_aggregated_instances(
        self, project_id: str, *, max_items: int = 500
    ) -> list[dict[str, Any]]:
        client = self._compute_client("instances", compute_v1.InstancesClient)
        out: list[dict[str, Any]] = []
        try:
            request = compute_v1.AggregatedListInstancesRequest(project=project_id)
            for _scope, scoped in client.aggregated_list(request=request):
                for inst in scoped.instances or []:
                    row = self._proto_to_dict(inst)
                    zone = row.get("zone", "")
                    if zone:
                        row["_ventra_zone"] = zone.rsplit("/", 1)[-1]
                    out.append(row)
                    if len(out) >= max_items:
                        return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_aggregated_disks(
        self, project_id: str, *, max_items: int = 500
    ) -> list[dict[str, Any]]:
        client = self._compute_client("disks", compute_v1.DisksClient)
        out: list[dict[str, Any]] = []
        try:
            request = compute_v1.AggregatedListDisksRequest(project=project_id)
            for _scope, scoped in client.aggregated_list(request=request):
                for disk in scoped.disks or []:
                    row = self._proto_to_dict(disk)
                    zone = row.get("zone", "")
                    if zone:
                        row["_ventra_zone"] = zone.rsplit("/", 1)[-1]
                    out.append(row)
                    if len(out) >= max_items:
                        return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_snapshots(self, project_id: str, *, max_items: int = 500) -> list[dict[str, Any]]:
        client = self._compute_client("snapshots", compute_v1.SnapshotsClient)
        out: list[dict[str, Any]] = []
        try:
            request = compute_v1.ListSnapshotsRequest(project=project_id)
            for snap in client.list(request=request):
                out.append(self._proto_to_dict(snap))
                if len(out) >= max_items:
                    return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_networks(self, project_id: str, *, max_items: int = 200) -> list[dict[str, Any]]:
        return self._list_compute(
            client_name="networks",
            client_factory=compute_v1.NetworksClient,
            list_method="list",
            request=compute_v1.ListNetworksRequest(project=project_id),
            max_items=max_items,
        )

    def compute_subnetworks(self, project_id: str, *, max_items: int = 500) -> list[dict[str, Any]]:
        client = self._compute_client("subnetworks", compute_v1.SubnetworksClient)
        out: list[dict[str, Any]] = []
        try:
            request = compute_v1.AggregatedListSubnetworksRequest(project=project_id)
            for _scope, scoped in client.aggregated_list(request=request):
                for subnet in scoped.subnetworks or []:
                    row = self._proto_to_dict(subnet)
                    region = row.get("region", "")
                    if region:
                        row["_ventra_region"] = region.rsplit("/", 1)[-1]
                    out.append(row)
                    if len(out) >= max_items:
                        return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_routes(self, project_id: str, *, max_items: int = 500) -> list[dict[str, Any]]:
        return self._list_compute(
            client_name="routes",
            client_factory=compute_v1.RoutesClient,
            list_method="list",
            request=compute_v1.ListRoutesRequest(project=project_id),
            max_items=max_items,
        )

    def compute_firewalls(self, project_id: str, *, max_items: int = 500) -> list[dict[str, Any]]:
        return self._list_compute(
            client_name="firewalls",
            client_factory=compute_v1.FirewallsClient,
            list_method="list",
            request=compute_v1.ListFirewallsRequest(project=project_id),
            max_items=max_items,
        )

    def compute_packet_mirrorings(
        self, project_id: str, *, max_items: int = 200
    ) -> list[dict[str, Any]]:
        return self._list_compute(
            client_name="packet_mirrorings",
            client_factory=compute_v1.PacketMirroringsClient,
            list_method="list",
            request=compute_v1.ListPacketMirroringsRequest(project=project_id),
            max_items=max_items,
        )

    def compute_security_policies(
        self, project_id: str, *, max_items: int = 200
    ) -> list[dict[str, Any]]:
        return self._list_compute(
            client_name="security_policies",
            client_factory=compute_v1.SecurityPoliciesClient,
            list_method="list",
            request=compute_v1.ListSecurityPoliciesRequest(project=project_id),
            max_items=max_items,
        )

    def list_gke_clusters(self, project_id: str, *, max_items: int = 200) -> list[dict[str, Any]]:
        from google.cloud import container_v1

        client = self._compute_client("container", container_v1.ClusterManagerClient)
        out: list[dict[str, Any]] = []
        try:
            parent = f"projects/{project_id}/locations/-"
            for cluster in client.list_clusters(parent=parent):
                row = self._proto_to_dict(cluster)
                if not row.get("location"):
                    name = str(row.get("name") or "")
                    if name.startswith("projects/"):
                        row["location"] = name.split("/")[3] if len(name.split("/")) > 3 else ""
                out.append(row)
                if len(out) >= max_items:
                    return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def list_log_sinks(self, project_id: str, *, max_items: int = 100) -> list[dict[str, Any]]:
        client = self._logging_client(project_id)
        out: list[dict[str, Any]] = []
        try:
            for sink in client.list_sinks():
                out.append(
                    {
                        "name": sink.name,
                        "destination": sink.destination,
                        "filter": sink.filter,
                        "includeChildren": sink.include_children,
                    }
                )
                if len(out) >= max_items:
                    break
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        except gcp_exc.NotFound as exc:
            raise GcpServiceNotEnabled(str(exc)) from exc
        return out
