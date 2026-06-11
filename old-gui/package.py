"""Evidence package reader and in-memory indexes.

Opens a collected evidence package (directory or .zip), exposes the manifest
and files read-only, and builds search indexes for CloudTrail events,
security findings, and IAM data. The viewer never modifies the package.
"""

import json
import os
import tempfile
import zipfile

MAX_FILE_VIEW_BYTES = 5 * 1024 * 1024


class PackageReader:
    """Read-only access to one evidence package."""

    def __init__(self, path):
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.exists(path):
            raise FileNotFoundError(f"package not found: {path}")
        if zipfile.is_zipfile(path):
            self._tempdir = tempfile.TemporaryDirectory(prefix="ir-viewer-")
            with zipfile.ZipFile(path) as archive:
                archive.extractall(self._tempdir.name)
            path = self._tempdir.name
        else:
            self._tempdir = None
        self.root = self._find_root(path)
        self.manifest = self._load_manifest()
        self._cloudtrail_index = None
        self._findings_index = None

    @staticmethod
    def _find_root(path):
        """Locate the directory that contains manifest.json."""
        if os.path.isfile(os.path.join(path, "manifest.json")):
            return path
        for entry in sorted(os.listdir(path)):
            candidate = os.path.join(path, entry)
            if os.path.isdir(candidate) and os.path.isfile(
                    os.path.join(candidate, "manifest.json")):
                return candidate
        raise FileNotFoundError(
            f"no manifest.json found in {path}; is this an evidence package?")

    def _load_manifest(self):
        with open(os.path.join(self.root, "manifest.json"),
                  encoding="utf-8") as handle:
            return json.load(handle)

    # --------------------------------------------------------------- files

    def safe_path(self, relative_path):
        """Resolve a package-relative path, refusing traversal outside root."""
        full = os.path.abspath(os.path.join(self.root, relative_path))
        if not full.startswith(os.path.abspath(self.root) + os.sep):
            raise PermissionError(f"path outside package: {relative_path}")
        return full

    def read_json(self, relative_path):
        with open(self.safe_path(relative_path), encoding="utf-8") as handle:
            return json.load(handle)

    def read_file_for_view(self, relative_path):
        """Return file content for display, truncated for very large files."""
        full = self.safe_path(relative_path)
        size = os.path.getsize(full)
        truncated = size > MAX_FILE_VIEW_BYTES
        with open(full, "rb") as handle:
            data = handle.read(MAX_FILE_VIEW_BYTES)
        text = data.decode("utf-8", errors="replace")
        return {"path": relative_path, "size": size,
                "truncated": truncated, "content": text}

    def list_files(self):
        """All files in the package, from disk (manifest may not list itself)."""
        entries = []
        hashes = {info["path"]: info.get("sha256")
                  for info in self.manifest.get("files", [])}
        for dirpath, _dirs, files in os.walk(self.root):
            for filename in sorted(files):
                full = os.path.join(dirpath, filename)
                relative = os.path.relpath(full, self.root).replace(os.sep, "/")
                entries.append({
                    "path": relative,
                    "size": os.path.getsize(full),
                    "sha256": hashes.get(relative),
                })
        entries.sort(key=lambda entry: entry["path"])
        return entries

    def _json_files_under(self, prefix):
        base = os.path.join(self.root, prefix)
        if not os.path.isdir(base):
            return
        for dirpath, _dirs, files in os.walk(base):
            for filename in sorted(files):
                if filename.endswith(".json"):
                    full = os.path.join(dirpath, filename)
                    relative = os.path.relpath(full, self.root).replace(os.sep, "/")
                    try:
                        with open(full, encoding="utf-8") as handle:
                            yield relative, json.load(handle)
                    except (OSError, ValueError):
                        continue

    # ----------------------------------------------------- cloudtrail index

    @property
    def cloudtrail_index(self):
        if self._cloudtrail_index is None:
            self._cloudtrail_index = self._build_cloudtrail_index()
        return self._cloudtrail_index

    def _build_cloudtrail_index(self):
        """Merge CloudTrail events from all collectors into one deduped index."""
        events = []
        seen_ids = set()
        sources = [
            "control_plane/cloudtrail_logs",
            "control_plane/sts_assume_role_activity",
            "control_plane/kms_key_activity",
            "control_plane/secrets_manager_activity",
            "control_plane/ssm_parameter_store_activity",
            "workload/ec2_disk_evidence",
        ]
        for prefix in sources:
            for relative, data in self._json_files_under(prefix):
                file_region = relative.split("/")[2] if len(
                    relative.split("/")) > 3 else ""
                event_lists = []
                if data.get("events"):
                    event_lists.append(data["events"])
                for value in data.values():
                    if isinstance(value, dict) and value.get("events"):
                        event_lists.append(value["events"])
                for raw in _flatten(event_lists):
                    if not isinstance(raw, dict) or "EventName" not in raw:
                        continue
                    event_id = raw.get("EventId")
                    if event_id and event_id in seen_ids:
                        continue
                    if event_id:
                        seen_ids.add(event_id)
                    detail = raw.get("CloudTrailEvent") or {}
                    if not isinstance(detail, dict):
                        detail = {}
                    identity = detail.get("userIdentity") or {}
                    events.append({
                        "idx": len(events),
                        "id": event_id,
                        "time": str(raw.get("EventTime") or
                                    detail.get("eventTime") or ""),
                        "name": raw.get("EventName", ""),
                        "source": (raw.get("EventSource") or
                                   detail.get("eventSource") or ""),
                        "user": (raw.get("Username") or
                                 identity.get("userName") or
                                 identity.get("arn") or ""),
                        "user_type": identity.get("type", ""),
                        "ip": detail.get("sourceIPAddress", ""),
                        "region": detail.get("awsRegion") or file_region,
                        "error": detail.get("errorCode", ""),
                        "read_only": str(raw.get("ReadOnly") or
                                         detail.get("readOnly") or ""),
                        "_raw": raw,
                    })
        events.sort(key=lambda event: event["time"], reverse=True)
        for index, event in enumerate(events):
            event["idx"] = index
        return events

    def cloudtrail_facets(self):
        """Distinct filter values with counts for the CloudTrail UI."""
        event_names = {}
        sources = {}
        regions = {}
        for event in self.cloudtrail_index:
            name = event["name"] or "unknown"
            event_names[name] = event_names.get(name, 0) + 1
            source = event["source"] or "unknown"
            sources[source] = sources.get(source, 0) + 1
            region = event["region"] or "unknown"
            regions[region] = regions.get(region, 0) + 1
        return {
            "total": len(self.cloudtrail_index),
            "event_names": _facet_list(event_names),
            "sources": _facet_list(sources),
            "regions": _facet_list(regions),
        }

    def query_cloudtrail(self, search="", names=None, sources=None, regions=None,
                         user="", ip="", errors_only=False, sort="time",
                         order="desc", limit=100, offset=0):
        results = []
        search = search.lower()
        name_set = {name.lower() for name in names} if names else None
        source_set = {source.lower() for source in sources} if sources else None
        region_set = set(regions) if regions else None
        for event in self.cloudtrail_index:
            if name_set and event["name"].lower() not in name_set:
                continue
            if source_set and (event["source"] or "").lower() not in source_set:
                continue
            if region_set and event["region"] not in region_set:
                continue
            if user and user.lower() not in event["user"].lower():
                continue
            if ip and ip not in event["ip"]:
                continue
            if errors_only and not event["error"]:
                continue
            if search:
                haystack = " ".join([
                    event["name"], event["user"], event["ip"],
                    event["source"], event["region"], event["error"],
                ]).lower()
                if search not in haystack:
                    continue
            results.append(event)
        reverse = order != "asc"
        if sort == "time":
            results.sort(key=lambda event: event["time"], reverse=reverse)
        total = len(results)
        page = [
            {key: value for key, value in event.items() if key != "_raw"}
            for event in results[offset:offset + limit]
        ]
        return {"total": total, "matched": total, "events": page}

    def cloudtrail_event(self, idx):
        if 0 <= idx < len(self.cloudtrail_index):
            return self.cloudtrail_index[idx]["_raw"]
        return None

    # ------------------------------------------------------ findings index

    @property
    def findings_index(self):
        if self._findings_index is None:
            self._findings_index = self._build_findings_index()
        return self._findings_index

    def _build_findings_index(self):
        findings = []

        for relative, data in self._json_files_under(
                "control_plane/guardduty_findings"):
            for raw in data.get("findings", []):
                severity = float(raw.get("Severity", 0) or 0)
                findings.append({
                    "idx": len(findings),
                    "source": "GuardDuty",
                    "severity": severity,
                    "severity_label": _guardduty_severity_label(severity),
                    "title": raw.get("Title", ""),
                    "type": raw.get("Type", ""),
                    "resource": (raw.get("Resource", {}) or {}).get(
                        "ResourceType", ""),
                    "region": raw.get("Region", ""),
                    "time": str(raw.get("UpdatedAt") or
                                raw.get("CreatedAt") or ""),
                    "file": relative,
                    "_raw": raw,
                })

        for relative, data in self._json_files_under(
                "control_plane/securityhub_findings"):
            for raw in data.get("findings", []):
                severity_info = raw.get("Severity", {}) or {}
                normalized = float(severity_info.get("Normalized", 0) or 0)
                resources = raw.get("Resources") or [{}]
                findings.append({
                    "idx": len(findings),
                    "source": "SecurityHub",
                    "severity": normalized / 10.0,
                    "severity_label": (severity_info.get("Label") or
                                       _hub_severity_label(normalized)),
                    "title": raw.get("Title", ""),
                    "type": ", ".join(raw.get("Types", [])[:1]),
                    "resource": resources[0].get("Type", ""),
                    "region": raw.get("Region", ""),
                    "time": str(raw.get("UpdatedAt") or ""),
                    "file": relative,
                    "_raw": raw,
                })

        for prefix, label in (
                ("control_plane/inspector_findings", "Inspector"),
                ("control_plane/macie_findings", "Macie")):
            for relative, data in self._json_files_under(prefix):
                for raw in data.get("findings", []):
                    severity_label = str(
                        raw.get("severity", {}).get("description")
                        if isinstance(raw.get("severity"), dict)
                        else raw.get("severity", "")) or "UNKNOWN"
                    findings.append({
                        "idx": len(findings),
                        "source": label,
                        "severity": _label_to_score(severity_label),
                        "severity_label": severity_label.upper(),
                        "title": raw.get("title", ""),
                        "type": raw.get("type", ""),
                        "resource": "",
                        "region": raw.get("region", ""),
                        "time": str(raw.get("updatedAt") or ""),
                        "file": relative,
                        "_raw": raw,
                    })

        findings.sort(key=lambda finding: finding["severity"], reverse=True)
        for index, finding in enumerate(findings):
            finding["idx"] = index
        return findings

    def query_findings(self, search="", source="", severity="",
                       limit=200, offset=0):
        results = []
        search = search.lower()
        for finding in self.findings_index:
            if source and finding["source"] != source:
                continue
            if severity and finding["severity_label"] != severity:
                continue
            if search:
                haystack = " ".join([
                    finding["title"], finding["type"], finding["resource"],
                    finding["region"],
                ]).lower()
                if search not in haystack:
                    continue
            results.append(finding)
        total = len(results)
        page = [
            {key: value for key, value in finding.items() if key != "_raw"}
            for finding in results[offset:offset + limit]
        ]
        return {"total": total, "findings": page}

    def finding(self, idx):
        if 0 <= idx < len(self.findings_index):
            return self.findings_index[idx]["_raw"]
        return None

    # -------------------------------------------------------------- identity

    def iam_summary(self):
        summary = {"users": [], "access_keys": [], "counts": {},
                   "credential_report_generated": None}
        try:
            report = self.read_json(
                "control_plane/iam_credential_report/credential_report.json")
            summary["users"] = report.get("users", [])
            summary["credential_report_generated"] = report.get(
                "generated_time")
        except (OSError, ValueError):
            pass
        try:
            keys = self.read_json(
                "control_plane/iam_snapshot/access_keys.json")
            summary["access_keys"] = keys.get("access_keys", [])
        except (OSError, ValueError):
            pass
        try:
            details = self.read_json(
                "control_plane/iam_snapshot/account_authorization_details.json")
            summary["counts"] = {
                "users": len(details.get("UserDetailList", [])),
                "groups": len(details.get("GroupDetailList", [])),
                "roles": len(details.get("RoleDetailList", [])),
                "policies": len(details.get("Policies", [])),
            }
        except (OSError, ValueError):
            pass
        return summary

    # ------------------------------------------------------------- workload

    def workload_summary(self):
        """Summarize Phase 4 workload collectors for the viewer."""
        summary = {
            "ec2_instances": [],
            "shared_snapshots": [],
            "ecs_clusters": 0,
            "eks_clusters": 0,
            "rds_instances": 0,
            "rds_clusters": 0,
            "collectors": [],
        }
        for relative, data in self._json_files_under(
                "workload/ec2_metadata_inventory"):
            region = relative.split("/")[2] if len(relative.split("/")) > 3 else ""
            for instance in data.get("instances", []):
                summary["ec2_instances"].append({
                    "instance_id": instance.get("InstanceId"),
                    "region": region,
                    "state": (instance.get("State") or {}).get("Name", ""),
                    "type": instance.get("InstanceType", ""),
                    "platform": instance.get("Platform", "linux"),
                    "private_ip": instance.get("PrivateIpAddress", ""),
                    "public_ip": instance.get("PublicIpAddress", ""),
                    "launch_time": str(instance.get("LaunchTime") or ""),
                    "iam_profile": (instance.get("IamInstanceProfile") or {}).get(
                        "Arn", ""),
                    "has_user_data": bool(
                        (data.get("user_data") or {}).get(
                            instance.get("InstanceId"))),
                })

        for relative, data in self._json_files_under(
                "workload/ec2_disk_evidence"):
            region = relative.split("/")[2] if len(relative.split("/")) > 3 else ""
            if "snapshots.json" in relative:
                for entry in data.get("shared_snapshots", []):
                    shared = entry.get("shared_with") or entry.get(
                        "restorable_by") or []
                    if shared:
                        summary["shared_snapshots"].append({
                            "region": region,
                            "snapshot_id": (entry.get("snapshot_id")
                                            or entry.get("cluster_snapshot")),
                            "shared_with": shared,
                        })

        for relative, data in self._json_files_under("workload/ecs_fargate_logs"):
            if relative.endswith("clusters.json"):
                summary["ecs_clusters"] += data.get("cluster_count", 0)

        for relative, data in self._json_files_under(
                "workload/eks_kubernetes_logs"):
            if relative.endswith("cluster.json"):
                summary["eks_clusters"] += 1

        for relative, data in self._json_files_under("workload/rds_aurora_logs"):
            if relative.endswith("inventory.json"):
                summary["rds_instances"] += data.get("instance_count", 0)
                summary["rds_clusters"] += data.get("cluster_count", 0)
            if relative.endswith("snapshots.json"):
                for entry in data.get("shared_snapshots", []):
                    shared = entry.get("restorable_by") or entry.get(
                        "shared_with") or []
                    if shared:
                        summary["shared_snapshots"].append({
                            "region": relative.split("/")[2]
                            if len(relative.split("/")) > 3 else "",
                            "snapshot_id": (entry.get("snapshot")
                                            or entry.get("cluster_snapshot")),
                            "shared_with": shared,
                        })

        for entry in self.manifest.get("collectors", []):
            if entry.get("category") == "workload":
                summary["collectors"].append(entry)
        return summary

    def cloudtrail_data_coverage(self):
        """Summarize CloudTrail S3 data event configuration and collection."""
        regions = {}
        for relative, data in self._json_files_under("control_plane/cloudtrail_logs"):
            if relative.endswith("data_events_coverage.json"):
                region = data.get("region") or (
                    relative.split("/")[2] if len(relative.split("/")) > 3 else "")
                regions[region] = data

        try:
            preflight = self.read_json("preflight/discovery.json")
        except (OSError, ValueError, PermissionError):
            preflight = {}

        for region, status in (preflight.get("logging_status") or {}).items():
            cloudtrail = status.get("cloudtrail") or {}
            if region not in regions:
                regions[region] = {
                    "region": region,
                    "s3_data_events_configured": cloudtrail.get(
                        "s3_data_events_configured"),
                    "source": "preflight",
                }

        configured = any(
            item.get("s3_data_events_configured") for item in regions.values())
        collected = sum(item.get("events_collected", 0) for item in regions.values())
        warnings = []
        if not configured:
            warnings.append(
                "CloudTrail S3 data events are not configured — object-level S3 "
                "access (GetObject/PutObject/DeleteObject) will not appear in the "
                "timeline.")
        elif collected == 0:
            warnings.append(
                "S3 data events are configured but no data-event log files were "
                "found in the incident window for the scoped regions.")

        return {
            "s3_data_events_configured": configured,
            "s3_data_events_collected": collected,
            "warnings": warnings,
            "regions": regions,
        }

    # --------------------------------------------------------- application

    def application_summary(self):
        summary = {"configured": False, "total_records": 0,
                   "cloudwatch_groups": [], "s3_locations": [],
                   "collectors": []}
        for relative, data in self._json_files_under(
                "application/application_logs"):
            if relative.endswith("collection_report.json"):
                summary["configured"] = True
                summary["total_records"] = data.get("total_records", 0)
                summary["cloudwatch_groups"] = data.get(
                    "cloudwatch_log_groups", [])
                summary["s3_locations"] = data.get("s3_locations", [])
            if relative.endswith("app_config_template.json"):
                summary["template_available"] = True
        for entry in self.manifest.get("collectors", []):
            if entry.get("category") == "application":
                summary["collectors"].append(entry)
        return summary

    # --------------------------------------------------------------- idp

    def idp_summary(self):
        summary = {"providers": [], "total_events": 0, "collectors": []}
        provider_map = {
            "okta_logs": ("Okta", "system_log.json", "events"),
            "entra_id_logs": ("Entra ID", None, None),
            "google_workspace_logs": ("Google Workspace", None, None),
            "onelogin_logs": ("OneLogin", "events.json", "events"),
            "ping_logs": ("PingOne", "audit_activities.json", "events"),
        }
        for entry in self.manifest.get("collectors", []):
            if entry.get("category") != "third_party_idp":
                continue
            summary["collectors"].append(entry)
            name = entry.get("name")
            label, primary_file, events_key = provider_map.get(
                name, (name, None, "events"))
            status = (entry.get("results") or [{}])[0].get("status", "unknown")
            event_count = 0
            if status == "collected":
                prefix = f"third_party_idp/{name}"
                if name == "entra_id_logs":
                    for relative, data in self._json_files_under(prefix):
                        if "signin_logs.json" in relative:
                            event_count += data.get("record_count", 0)
                        if "directory_audit_logs.json" in relative:
                            event_count += data.get("record_count", 0)
                elif name == "google_workspace_logs":
                    for relative, data in self._json_files_under(prefix):
                        if relative.endswith("_activity.json"):
                            event_count += data.get("record_count", 0)
                elif primary_file:
                    for relative, data in self._json_files_under(prefix):
                        if relative.endswith(primary_file):
                            event_count += data.get(
                                "event_count", len(data.get(events_key, [])))
            summary["providers"].append({
                "name": name,
                "label": label,
                "status": status,
                "event_count": event_count,
            })
            summary["total_events"] += event_count
        return summary


def _facet_list(counter):
    return sorted(
        [{"value": key, "count": count} for key, count in counter.items()],
        key=lambda entry: (-entry["count"], entry["value"]),
    )


def _flatten(lists):
    for items in lists:
        for item in items:
            yield item


def _guardduty_severity_label(score):
    if score >= 8:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFORMATIONAL"


def _hub_severity_label(normalized):
    if normalized >= 90:
        return "CRITICAL"
    if normalized >= 70:
        return "HIGH"
    if normalized >= 40:
        return "MEDIUM"
    if normalized >= 1:
        return "LOW"
    return "INFORMATIONAL"


def _label_to_score(label):
    return {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0,
            "LOW": 2.0}.get(str(label).upper(), 0.0)
