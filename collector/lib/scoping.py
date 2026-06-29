"""Resource scoping helpers applied from per-artifact parameters."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from .params import matches_any, matches_prefix, param_int, param_raw, param_strings

_BLOB_HOUR_RE = re.compile(r"/y=(\d{4})/m=(\d{2})/d=(\d{2})/h=(\d{2})/")


def filter_cloudtrail_trails(trails: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    arns = param_strings(params, "trail_arns")
    names = param_strings(params, "trail_names")
    buckets = param_strings(params, "s3_bucket_names")
    if not (arns or names or buckets):
        return trails
    kept: list[dict[str, Any]] = []
    for trail in trails:
        trail_arn = str(trail.get("TrailARN") or "")
        trail_name = str(trail.get("Name") or "")
        bucket = str(trail.get("S3BucketName") or "")
        if arns and not matches_any(trail_arn, arns):
            continue
        if names and not matches_any(trail_name, names):
            continue
        if buckets and not matches_any(bucket, buckets):
            continue
        kept.append(trail)
    return kept


def cloudtrail_event_matches(params: dict[str, Any], rec: dict[str, Any]) -> bool:
    """Post-fetch filter for CloudTrail event records."""
    event_names = param_strings(params, "event_names")
    if event_names:
        name = str(rec.get("eventName") or "")
        if not any(matches_any(name, [n]) for n in event_names):
            return False

    usernames = param_strings(params, "username")
    if usernames:
        uid = rec.get("userIdentity") or {}
        candidates = [
            str(uid.get("userName") or ""),
            str(uid.get("arn") or ""),
            str(uid.get("principalId") or ""),
        ]
        if not any(matches_any(c, usernames) for c in candidates if c):
            return False

    identity_arns = param_strings(params, "user_identity_arn")
    if identity_arns:
        arn = str((rec.get("userIdentity") or {}).get("arn") or "")
        if not matches_any(arn, identity_arns):
            return False

    return True


def filter_vpc_flow_logs(
    flow_logs: list[dict[str, Any]],
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    vpc_ids = param_strings(params, "vpc_ids")
    flow_log_ids = param_strings(params, "flow_log_ids")
    log_groups = param_strings(params, "log_group_names")
    s3_buckets = param_strings(params, "s3_bucket_names")
    dest_type = param_strings(params, "destination_type")
    if not (vpc_ids or flow_log_ids or log_groups or s3_buckets or dest_type):
        return flow_logs
    kept: list[dict[str, Any]] = []
    for fl in flow_logs:
        rid = str(fl.get("ResourceId") or "")
        fid = str(fl.get("FlowLogId") or "")
        group = str(fl.get("LogGroupName") or "")
        dest = str(fl.get("LogDestination") or "")
        dtype = str(fl.get("LogDestinationType") or "")
        if vpc_ids and not matches_any(rid, vpc_ids):
            continue
        if flow_log_ids and not matches_any(fid, flow_log_ids):
            continue
        if log_groups and not matches_any(group, log_groups):
            continue
        if s3_buckets and not any(b in dest for b in s3_buckets):
            continue
        if dest_type:
            normalized = {d.lower().replace("_", "-") for d in dest_type}
            if dtype.lower().replace("_", "-") not in normalized:
                continue
        kept.append(fl)
    return kept


def filter_gke_clusters(clusters: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    names = param_strings(params, "cluster_names")
    ids = param_strings(params, "cluster_ids")
    locations = param_strings(params, "locations")
    if not (names or ids or locations):
        return clusters
    kept: list[dict[str, Any]] = []
    for c in clusters:
        name = str(c.get("name") or "")
        cid = str(c.get("id") or c.get("selfLink") or "")
        location = str(c.get("location") or "")
        if names and not matches_any(name, names):
            continue
        if ids and not matches_any(cid, ids):
            continue
        if locations and not matches_any(location, locations):
            continue
        kept.append(c)
    return kept


def filter_eks_clusters(clusters: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    names = param_strings(params, "cluster_names")
    arns = param_strings(params, "cluster_arns")
    log_groups = param_strings(params, "log_group_names")
    if not (names or arns or log_groups):
        return clusters
    kept: list[dict[str, Any]] = []
    for c in clusters:
        name = str(c.get("name") or "")
        arn = str(c.get("arn") or "")
        group = f"/aws/eks/{name}/cluster"
        if names and not matches_any(name, names):
            continue
        if arns and not matches_any(arn, arns):
            continue
        if log_groups and not matches_any(group, log_groups):
            continue
        kept.append(c)
    return kept


def filter_s3_buckets(buckets: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    names = param_strings(params, "bucket_names") + param_strings(params, "source_bucket_names")
    prefixes = param_strings(params, "name_prefix")
    if not (names or prefixes):
        return buckets
    kept: list[dict[str, Any]] = []
    for b in buckets:
        name = str(b.get("Name") or b.get("name") or "")
        if names and not matches_any(name, names):
            continue
        if prefixes and not matches_prefix(name, prefixes):
            continue
        kept.append(b)
    return kept


def filter_by_name_or_id(
    items: list[dict[str, Any]],
    params: dict[str, Any],
    *,
    name_keys: tuple[str, ...] = ("name", "Name"),
    id_keys: tuple[str, ...] = ("id", "Id"),
    arn_keys: tuple[str, ...] = ("arn", "Arn", "ARN"),
    name_param: str = "names",
    id_param: str = "resource_ids",
    arn_param: str = "resource_arns",
) -> list[dict[str, Any]]:
    names = param_strings(params, name_param)
    ids = param_strings(params, id_param)
    arns = param_strings(params, arn_param)
    prefixes = param_strings(params, "name_prefix")
    if not (names or ids or arns or prefixes):
        return items
    kept: list[dict[str, Any]] = []
    for item in items:
        item_names = [str(item.get(k) or "") for k in name_keys if item.get(k)]
        item_ids = [str(item.get(k) or "") for k in id_keys if item.get(k)]
        item_arns = [str(item.get(k) or "") for k in arn_keys if item.get(k)]
        if names and not any(matches_any(n, names) for n in item_names):
            continue
        if ids and not any(matches_any(i, ids) for i in item_ids):
            continue
        if arns and not any(matches_any(a, arns) for a in item_arns):
            continue
        if prefixes and not any(matches_prefix(n, prefixes) for n in item_names):
            continue
        kept.append(item)
    return kept


def filter_iam_users(users: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    return filter_by_name_or_id(
        users, params, name_keys=("UserName",), name_param="user_names"
    )


def filter_iam_roles(roles: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    names = param_strings(params, "role_names")
    arns = param_strings(params, "role_arns")
    if not (names or arns):
        return roles
    kept: list[dict[str, Any]] = []
    for role in roles:
        rname = str(role.get("RoleName") or "")
        rarn = str(role.get("Arn") or "")
        if names and not matches_any(rname, names):
            continue
        if arns and not matches_any(rarn, arns):
            continue
        kept.append(role)
    return kept


def filter_iam_policies(policies: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    return filter_by_name_or_id(
        policies, params, arn_keys=("Arn",), arn_param="policy_arns"
    )


def filter_lambda_functions(functions: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    return filter_by_name_or_id(
        functions,
        params,
        name_keys=("FunctionName",),
        arn_keys=("FunctionArn",),
        name_param="function_names",
        arn_param="function_arns",
    )


def filter_apigateway_stages(stages: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    api_ids = param_strings(params, "api_ids")
    api_names = param_strings(params, "api_names")
    stage_names = param_strings(params, "stage_names")
    log_groups = param_strings(params, "log_group_names")
    if not (api_ids or api_names or stage_names or log_groups):
        return stages
    kept: list[dict[str, Any]] = []
    for stage in stages:
        api_id = str(stage.get("api_id") or "")
        api_name = str(stage.get("api_name") or "")
        stage_name = str(stage.get("stage_name") or "")
        group = str(stage.get("log_group") or "")
        if api_ids and not matches_any(api_id, api_ids):
            continue
        if api_names and not matches_any(api_name, api_names):
            continue
        if stage_names and not matches_any(stage_name, stage_names):
            continue
        if log_groups and group and not matches_any(group, log_groups):
            continue
        if log_groups and not group:
            continue
        kept.append(stage)
    return kept


def filter_lambda_log_targets(targets: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    names = param_strings(params, "function_names")
    arns = param_strings(params, "function_arns")
    log_groups = param_strings(params, "log_group_names")
    if not (names or arns or log_groups):
        return targets
    kept: list[dict[str, Any]] = []
    for target in targets:
        name = str(target.get("function_name") or "")
        arn = str(target.get("function_arn") or "")
        group = str(target.get("log_group") or "")
        if names and not matches_any(name, names):
            continue
        if arns and not matches_any(arn, arns):
            continue
        if log_groups and not matches_any(group, log_groups):
            continue
        kept.append(target)
    return kept


def filter_rds_log_targets(instances: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    instance_ids = param_strings(params, "db_instance_ids")
    instance_arns = param_strings(params, "db_instance_arns")
    log_groups = param_strings(params, "log_group_names")
    log_types = param_strings(params, "log_types")
    if not (instance_ids or instance_arns or log_groups or log_types):
        return instances
    kept: list[dict[str, Any]] = []
    for inst in instances:
        iid = str(inst.get("instance_id") or "")
        arn = str(inst.get("instance_arn") or "")
        exports = [str(x) for x in (inst.get("log_exports") or [])]
        if instance_ids and not matches_any(iid, instance_ids):
            continue
        if instance_arns and not matches_any(arn, instance_arns):
            continue
        if log_types:
            if not exports:
                continue
            if not any(matches_any(e, log_types) for e in exports):
                continue
            inst = {**inst, "log_exports": [e for e in exports if matches_any(e, log_types)]}
        if log_groups:
            groups = [
                _log_group_for_rds_instance(iid, lt)
                for lt in (inst.get("log_exports") or exports)
            ]
            if groups and not any(matches_any(g, log_groups) for g in groups):
                continue
        kept.append(inst)
    return kept


def _log_group_for_rds_instance(instance_id: str, log_type: str) -> str:
    return f"/aws/rds/instance/{instance_id}/{log_type}"


def filter_secrets(secrets: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    return filter_by_name_or_id(
        secrets,
        params,
        name_keys=("Name",),
        arn_keys=("ARN",),
        name_param="secret_names",
        arn_param="secret_arns",
    )


def filter_kms_keys(keys: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    key_ids = param_strings(params, "key_ids")
    key_arns = param_strings(params, "key_arns")
    aliases = param_strings(params, "alias_names")
    if not (key_ids or key_arns or aliases):
        return keys
    kept: list[dict[str, Any]] = []
    for entry in keys:
        kid = str(entry.get("key_id") or "")
        meta = entry.get("metadata") or {}
        arn = str(meta.get("Arn") or "")
        if key_ids and not matches_any(kid, key_ids) and not matches_any(arn, key_ids):
            continue
        if key_arns and not matches_any(arn, key_arns):
            continue
        if aliases:
            alias_list = [str(a.get("AliasName") or "") for a in (entry.get("aliases") or [])]
            if not any(matches_any(a, aliases) for a in alias_list if a):
                continue
        kept.append(entry)
    return kept


def filter_config_compliance(compliance: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    rules = param_strings(params, "config_rule_names")
    if not rules:
        return compliance
    kept: list[dict[str, Any]] = []
    for c in compliance:
        name = str(c.get("ConfigRuleName") or "")
        if matches_any(name, rules):
            kept.append(c)
    return kept


def filter_elb_load_balancers(lbs: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    arns = param_strings(params, "load_balancer_arns")
    names = param_strings(params, "load_balancer_names")
    buckets = param_strings(params, "s3_bucket_names")
    if not (arns or names or buckets):
        return lbs
    kept: list[dict[str, Any]] = []
    for lb in lbs:
        larn = str(lb.get("LoadBalancerArn") or lb.get("arn") or "")
        lname = str(lb.get("LoadBalancerName") or lb.get("name") or "")
        bucket = str(lb.get("access_log_bucket") or lb.get("s3_bucket") or "")
        if arns and not matches_any(larn, arns):
            continue
        if names and not matches_any(lname, names):
            continue
        if buckets and bucket and not matches_any(bucket, buckets):
            continue
        kept.append(lb)
    return kept


def filter_cloudfront_distributions(dists: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    ids = param_strings(params, "distribution_ids")
    domains = param_strings(params, "domain_names")
    if not (ids or domains):
        return dists
    kept: list[dict[str, Any]] = []
    for d in dists:
        did = str(d.get("Id") or d.get("id") or "")
        domain = str(d.get("DomainName") or d.get("domain_name") or "")
        aliases = [str(a) for a in (d.get("Aliases") or d.get("aliases") or {}).get("Items") or []]
        if ids and not matches_any(did, ids):
            continue
        if domains and not (
            matches_any(domain, domains) or any(matches_any(a, domains) for a in aliases)
        ):
            continue
        kept.append(d)
    return kept


def filter_route53_query_log_configs(
    configs: list[dict[str, Any]], params: dict[str, Any]
) -> list[dict[str, Any]]:
    config_ids = param_strings(params, "query_log_config_ids")
    vpc_ids = param_strings(params, "vpc_ids")
    if not (config_ids or vpc_ids):
        return configs
    kept: list[dict[str, Any]] = []
    for cfg in configs:
        cid = str(cfg.get("Id") or "")
        if config_ids and not matches_any(cid, config_ids):
            continue
        if vpc_ids:
            cfg_vpcs = [str(v.get("VpcId") or v) for v in (cfg.get("DestinationArn") or cfg.get("vpcs") or [])]
            if isinstance(cfg.get("vpcs"), list):
                cfg_vpcs = [str(v) for v in cfg["vpcs"]]
            assoc = cfg.get("Associations") or cfg.get("associations") or []
            cfg_vpcs.extend(str(a.get("VpcId") or "") for a in assoc if isinstance(a, dict))
            if cfg_vpcs and not any(matches_any(v, vpc_ids) for v in cfg_vpcs if v):
                continue
        kept.append(cfg)
    return kept


def filter_waf_acls(acls: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    return filter_by_name_or_id(
        acls,
        params,
        name_keys=("Name",),
        arn_keys=("ARN", "Arn"),
        name_param="web_acl_names",
        arn_param="web_acl_arns",
    )


def filter_ec2_inventory(inventory: dict[str, list], params: dict[str, Any]) -> dict[str, list]:
    instance_ids = param_strings(params, "instance_ids")
    vpc_ids = param_strings(params, "vpc_ids")
    sg_ids = param_strings(params, "security_group_ids")
    snapshot_ids = param_strings(params, "snapshot_ids")

    if instance_ids:
        inventory["instances"] = [
            i for i in inventory["instances"]
            if matches_any(str(i.get("InstanceId") or ""), instance_ids)
        ]
    if vpc_ids:
        inventory["instances"] = [
            i for i in inventory["instances"]
            if matches_any(str(i.get("VpcId") or ""), vpc_ids)
        ]
    if sg_ids:
        inventory["security_groups"] = [
            sg for sg in inventory["security_groups"]
            if matches_any(str(sg.get("GroupId") or ""), sg_ids)
        ]
    if snapshot_ids:
        inventory["snapshots"] = [
            s for s in inventory["snapshots"]
            if matches_any(str(s.get("SnapshotId") or ""), snapshot_ids)
        ]
    return inventory


def filter_guardduty_findings(findings: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    finding_ids = param_strings(params, "finding_ids")
    finding_types = param_strings(params, "finding_types")
    resource_arns = param_strings(params, "resource_arns")
    severity_min = param_int(params, "severity_min")
    if not (finding_ids or finding_types or resource_arns or severity_min is not None):
        return findings
    kept: list[dict[str, Any]] = []
    for f in findings:
        fid = str(f.get("Id") or "")
        if finding_ids and not matches_any(fid, finding_ids):
            continue
        ftype = str(f.get("Type") or "")
        if finding_types and not matches_any(ftype, finding_types):
            continue
        if resource_arns:
            res = f.get("Resource") or {}
            res_str = str(res)
            if not any(matches_any(res_str, [a]) for a in resource_arns):
                continue
        if severity_min is not None:
            try:
                sev = float(f.get("Severity") or 0)
            except (TypeError, ValueError):
                sev = 0
            if sev < severity_min:
                continue
        kept.append(f)
    return kept


def filter_securityhub_findings(findings: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    severities = param_strings(params, "severity_label")
    product_arns = param_strings(params, "product_arns")
    resource_arns = param_strings(params, "resource_arns")
    finding_types = param_strings(params, "finding_types")
    if not (severities or product_arns or resource_arns or finding_types):
        return findings
    kept: list[dict[str, Any]] = []
    for f in findings:
        sev = str((f.get("Severity") or {}).get("Label") or "")
        if severities and not matches_any(sev, severities):
            continue
        prod = str(f.get("ProductArn") or "")
        if product_arns and not matches_any(prod, product_arns):
            continue
        ftype = str(f.get("Types") or f.get("Type") or "")
        if finding_types and not matches_any(ftype, finding_types):
            continue
        if resource_arns:
            resources = f.get("Resources") or []
            res_ids = [str(r.get("Id") or r.get("Arn") or "") for r in resources]
            if not any(matches_any(r, resource_arns) for r in res_ids if r):
                continue
        kept.append(f)
    return kept


def filter_macie_findings(findings: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    finding_ids = param_strings(params, "finding_ids")
    resource_arns = param_strings(params, "resource_arns")
    if not (finding_ids or resource_arns):
        return findings
    kept: list[dict[str, Any]] = []
    for f in findings:
        fid = str(f.get("id") or f.get("Id") or "")
        if finding_ids and not matches_any(fid, finding_ids):
            continue
        if resource_arns:
            bucket = str(((f.get("resourcesAffected") or {}).get("s3Bucket") or {}).get("arn") or "")
            if bucket and not matches_any(bucket, resource_arns):
                continue
        kept.append(f)
    return kept


def filter_inspector_findings(findings: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    resource_ids = param_strings(params, "resource_ids")
    ecr_repos = param_strings(params, "ecr_repository_names")
    if not (resource_ids or ecr_repos):
        return findings
    kept: list[dict[str, Any]] = []
    for f in findings:
        if resource_ids:
            resources = f.get("resources") or []
            rids = [str(r.get("id") or "") for r in resources]
            if not any(matches_any(r, resource_ids) for r in rids if r):
                continue
        if ecr_repos:
            found = False
            for r in f.get("resources") or []:
                details = r.get("details") or {}
                repo = str((details.get("awsEcrContainerImage") or {}).get("repositoryName") or "")
                if repo and matches_any(repo, ecr_repos):
                    found = True
                    break
            if not found:
                continue
        kept.append(f)
    return kept


def filter_detective_graphs(graphs: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    return filter_by_name_or_id(
        graphs, params, arn_keys=("Arn",), arn_param="graph_arns"
    )


def filter_detective_investigations(
    investigations: list[dict[str, Any]], params: dict[str, Any]
) -> list[dict[str, Any]]:
    ids = param_strings(params, "investigation_ids")
    if not ids:
        return investigations
    return [
        inv for inv in investigations
        if matches_any(str(inv.get("InvestigationId") or inv.get("investigationId") or ""), ids)
    ]


def filter_gce_inventory(inventory: dict[str, list], params: dict[str, Any]) -> dict[str, list]:
    instance_ids = param_strings(params, "instance_ids")
    zones = param_strings(params, "zones")
    network_names = param_strings(params, "network_names") + param_strings(params, "vpc_ids")
    snapshot_ids = param_strings(params, "snapshot_ids")

    if instance_ids:
        inventory["instances"] = [
            i
            for i in inventory["instances"]
            if matches_any(str(i.get("id") or i.get("name") or ""), instance_ids)
        ]
    if zones:
        inventory["instances"] = [
            i
            for i in inventory["instances"]
            if matches_any(str(i.get("_ventra_zone") or ""), zones)
        ]
    if network_names:
        inventory["instances"] = [
            i
            for i in inventory["instances"]
            if any(
                matches_any(str(nic.get("network") or ""), network_names)
                for nic in (i.get("networkInterfaces") or [])
                if isinstance(nic, dict)
            )
        ]
    if snapshot_ids:
        inventory["snapshots"] = [
            s
            for s in inventory["snapshots"]
            if matches_any(str(s.get("id") or s.get("name") or ""), snapshot_ids)
        ]
    if instance_ids or zones or network_names:
        allowed_instances = {
            str(i.get("id") or i.get("name") or "") for i in inventory["instances"]
        }
        inventory["network_interfaces"] = [
            nic
            for nic in inventory["network_interfaces"]
            if str(nic.get("_ventra_instance_id") or "") in allowed_instances
        ]
    return inventory


def filter_network_posture(snapshot: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    network_names = param_strings(params, "network_names") + param_strings(params, "vpc_ids")
    firewall_names = param_strings(params, "firewall_rule_names")
    if network_names:
        snapshot["networks"] = [
            n
            for n in snapshot.get("networks") or []
            if matches_any(str(n.get("name") or n.get("id") or ""), network_names)
            or matches_any(str(n.get("selfLink") or ""), network_names)
        ]
        snapshot["subnetworks"] = [
            s
            for s in snapshot.get("subnetworks") or []
            if matches_any(str(s.get("network") or ""), network_names)
        ]
        snapshot["routes"] = [
            r
            for r in snapshot.get("routes") or []
            if matches_any(str(r.get("network") or ""), network_names)
        ]
    if firewall_names:
        snapshot["firewall_rules"] = [
            f
            for f in snapshot.get("firewall_rules") or []
            if matches_any(str(f.get("name") or ""), firewall_names)
        ]
    return snapshot


def filter_iam_bindings(bindings: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    roles = param_strings(params, "roles")
    members = param_strings(params, "members")
    if not (roles or members):
        return bindings
    kept: list[dict[str, Any]] = []
    for b in bindings:
        role = str(b.get("role") or "")
        mems = [str(m) for m in (b.get("members") or [])]
        if roles and not matches_any(role, roles):
            continue
        if members and not any(matches_any(m, members) for m in mems):
            continue
        kept.append(b)
    return kept


def filter_scc_findings(findings: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    severities = param_strings(params, "severity")
    states = param_strings(params, "state")
    project_ids = param_strings(params, "project_ids")
    if not (severities or states or project_ids):
        return findings
    kept: list[dict[str, Any]] = []
    for f in findings:
        sev = str(f.get("severity") or "")
        if severities and not matches_any(sev, severities):
            continue
        state = str(f.get("state") or "")
        if states and not matches_any(state, states):
            continue
        if project_ids:
            res = str(f.get("resourceName") or f.get("name") or "")
            if not any(p in res for p in project_ids):
                continue
        kept.append(f)
    return kept


def filter_azure_resources(
    resources: list[dict[str, Any]],
    params: dict[str, Any],
    *,
    name_param: str = "resource_ids",
) -> list[dict[str, Any]]:
    ids = param_strings(params, "resource_ids")
    names: list[str] = []
    for key in (name_param, "bucket_names", "firewall_names", "vault_names", "profile_names", "names"):
        names.extend(param_strings(params, key))
    rgs = param_strings(params, "resource_group_names")
    if not (ids or names or rgs):
        return resources
    kept: list[dict[str, Any]] = []
    for res in resources:
        rid = str(res.get("id") or "")
        rname = str(res.get("name") or "")
        if ids and not matches_any(rid, ids):
            continue
        if names and not matches_any(rname, names) and not matches_any(rid, names):
            continue
        if rgs:
            lower = rid.lower()
            if not any(f"/resourcegroups/{rg.lower()}/" in lower for rg in rgs):
                continue
        kept.append(res)
    return kept


def filter_vnet_flow_logs(flow_logs: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    names = param_strings(params, "flow_log_names")
    targets = param_strings(params, "target_resource_ids")
    storage_ids = param_strings(params, "storage_account_ids")
    rgs = param_strings(params, "resource_group_names")
    if not (names or targets or storage_ids or rgs):
        return flow_logs
    kept: list[dict[str, Any]] = []
    for fl in flow_logs:
        fname = str(fl.get("name") or "")
        target = str(fl.get("target_resource_id") or "")
        storage = str(fl.get("storage_id") or "")
        if names and not matches_any(fname, names):
            continue
        if targets and not matches_any(target, targets):
            continue
        if storage_ids and not matches_any(storage, storage_ids):
            continue
        if rgs:
            rid = target.lower()
            if not any(f"/resourcegroups/{rg.lower()}/" in rid for rg in rgs):
                continue
        kept.append(fl)
    return kept


def filter_nsg_flow_logs(flow_logs: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    nsg_ids = param_strings(params, "nsg_resource_ids")
    storage_ids = param_strings(params, "storage_account_ids")
    if not (nsg_ids or storage_ids):
        return flow_logs
    kept: list[dict[str, Any]] = []
    for fl in flow_logs:
        target = str(fl.get("target_resource_id") or "")
        storage = str(fl.get("storage_id") or "")
        if nsg_ids and not matches_any(target, nsg_ids):
            continue
        if storage_ids and not matches_any(storage, storage_ids):
            continue
        kept.append(fl)
    return kept


def filter_defender_alerts(alerts: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    resource_ids = param_strings(params, "resource_ids")
    severities = param_strings(params, "severity")
    if not (resource_ids or severities):
        return alerts
    kept: list[dict[str, Any]] = []
    for a in alerts:
        props = a.get("properties") or a
        sev = str(props.get("severity") or props.get("alertSeverity") or "")
        if severities and not matches_any(sev, severities):
            continue
        if resource_ids:
            rid = str(props.get("resourceIdentifiers") or props.get("resourceId") or a.get("id") or "")
            if isinstance(props.get("resourceIdentifiers"), list):
                rid = " ".join(str(x.get("azureResourceId") or x) for x in props["resourceIdentifiers"])
            if not any(matches_any(rid, [r]) for r in resource_ids):
                continue
        kept.append(a)
    return kept


def filter_storage_access_records(
    records: list[dict[str, Any]], params: dict[str, Any]
) -> list[dict[str, Any]]:
    principals = param_strings(params, "principal_email")
    http_status = param_raw(params, "http_status")
    if not (principals or http_status):
        return records
    kept: list[dict[str, Any]] = []
    for rec in records:
        if principals:
            caller = str(rec.get("caller") or rec.get("identity") or rec.get("requester") or "")
            if not matches_any(caller, principals):
                continue
        if http_status is not None:
            status = str(rec.get("statusCode") or rec.get("status") or rec.get("httpStatusCode") or "")
            if status != str(http_status).strip():
                continue
        kept.append(rec)
    return kept


def blob_path_in_window(name: str, start: datetime | None, end: datetime | None) -> bool:
    """True when blob path has no hour segment or its hour falls within [start, end]."""
    if start is None and end is None:
        return True
    m = _BLOB_HOUR_RE.search(name)
    if not m:
        return True
    try:
        y, mo, d, h = (int(m.group(i)) for i in range(1, 5))
        blob_dt = datetime(y, mo, d, h, tzinfo=UTC)
    except ValueError:
        return True
    if start is not None and blob_dt < start.replace(minute=0, second=0, microsecond=0):
        return False
    if end is not None and blob_dt > end.replace(minute=0, second=0, microsecond=0):
        return False
    return True


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def arm_activity_log_filter(params: dict[str, Any], start: datetime, end: datetime) -> str:
    """Build ARM Activity Log OData filter with optional param clauses."""
    parts = [f"eventTimestamp ge '{_iso(start)}'", f"eventTimestamp le '{_iso(end)}'"]

    def _eq_list(field: str, key: str) -> None:
        vals = param_strings(params, key)
        if not vals:
            return
        if len(vals) == 1:
            parts.append(f"{field} eq '{vals[0]}'")
        else:
            inner = " or ".join(f"{field} eq '{v}'" for v in vals)
            parts.append(f"({inner})")

    _eq_list("resourceGroupName", "resource_group_names")
    _eq_list("correlationId", "correlation_id")
    _eq_list("caller", "caller")
    _eq_list("operationName", "operation_names")

    resource_ids = param_strings(params, "resource_ids")
    if resource_ids:
        inner = " or ".join(f"resourceId eq '{v}'" for v in resource_ids)
        parts.append(f"({inner})")

    categories = param_strings(params, "event_categories")
    if categories:
        inner = " or ".join(f"eventChannels eq '{c}'" for c in categories)
        parts.append(f"({inner})")

    return " and ".join(parts)


def graph_filter_clauses(params: dict[str, Any], *, field_map: dict[str, str]) -> list[str]:
    clauses: list[str] = []
    for param_key, graph_field in field_map.items():
        vals = param_strings(params, param_key)
        if not vals:
            continue
        if len(vals) == 1:
            clauses.append(f"{graph_field} eq '{vals[0]}'")
        else:
            inner = " or ".join(f"{graph_field} eq '{v}'" for v in vals)
            clauses.append(f"({inner})")
    return clauses


def graph_entra_signin_filter(params: dict[str, Any], start: datetime, end: datetime) -> str:
    from collector.engine.api.azure.common import graph_time_filter

    clauses = [graph_time_filter("createdDateTime", start, end)]
    clauses.extend(
        graph_filter_clauses(
            params,
            field_map={
                "user_principal_names": "userPrincipalName",
                "user_ids": "userId",
                "app_ids": "appId",
                "ip_address": "ipAddress",
            },
        )
    )
    return " and ".join(clauses)


def graph_entra_audit_filter(params: dict[str, Any], start: datetime, end: datetime) -> str:
    from collector.engine.api.azure.common import graph_time_filter

    clauses = [graph_time_filter("activityDateTime", start, end)]
    clauses.extend(
        graph_filter_clauses(
            params,
            field_map={
                "operation_names": "activityDisplayName",
                "category": "category",
            },
        )
    )
    return " and ".join(clauses)


def gcp_logging_filter_extension(params: dict[str, Any]) -> str:
    """Build extra Cloud Logging filter clauses from artifact params."""
    clauses: list[str] = []

    def _or_field(field: str, key: str) -> None:
        vals = param_strings(params, key)
        if not vals:
            return
        if len(vals) == 1:
            clauses.append(f'{field}="{vals[0]}"')
        else:
            inner = " OR ".join(f'{field}="{v}"' for v in vals)
            clauses.append(f"({inner})")

    mapping: list[tuple[str, str]] = [
        ("resource.labels.bucket_name", "bucket_names"),
        ("resource.labels.dataset_id", "dataset_ids"),
        ("resource.labels.table_id", "table_ids"),
        ("resource.labels.database_id", "instance_names"),
        ("resource.labels.secret_id", "secret_names"),
        ("resource.labels.subnetwork_name", "subnetwork_names"),
        ("resource.labels.instance_id", "instance_ids"),
        ("resource.labels.zone", "zones"),
        ("resource.labels.region", "regions"),
        ("resource.labels.function_name", "function_names"),
        ("resource.labels.gateway_id", "gateway_ids"),
        ("resource.labels.url_map_name", "url_map_names"),
        ("resource.labels.backend_service_name", "backend_service_names"),
        ("resource.labels.cluster_name", "cluster_names"),
        ("resource.labels.location", "locations"),
        ("resource.labels.target_name", "dns_zone_names"),
        ("resource.labels.gateway_name", "nat_gateway_names"),
        ("jsonPayload.enforcedSecurityPolicy.name", "security_policy_names"),
        ("protoPayload.resourceName", "resource_names"),
    ]
    for field, key in mapping:
        _or_field(field, key)

    resource_types = param_strings(params, "resource_types")
    if resource_types:
        inner = " OR ".join(f'resource.type="{t}"' for t in resource_types)
        clauses.append(f"({inner})")

    for key, field in (
        ("principal_email", "protoPayload.authenticationInfo.principalEmail"),
        ("user_email", "protoPayload.authenticationInfo.principalEmail"),
        ("source_ip", "protoPayload.requestMetadata.callerIp"),
        ("src_ip", "jsonPayload.connection.src_ip"),
        ("dest_ip", "jsonPayload.connection.dest_ip"),
        ("firewall_rule_names", "jsonPayload.rule_details.reference"),
        ("alert_policy_names", "resource.labels.alert_policy_id"),
        ("incident_ids", "jsonPayload.incident.incident_id"),
    ):
        vals = param_strings(params, key)
        if len(vals) == 1:
            clauses.append(f'{field}="{vals[0]}"')
        elif len(vals) > 1:
            _or_field(field, key)

    http_status = param_raw(params, "http_status")
    if http_status is not None and str(http_status).strip():
        clauses.append(f'httpRequest.status={str(http_status).strip()}')

    search_text = param_raw(params, "search_text")
    if isinstance(search_text, str) and search_text.strip():
        q = search_text.strip().replace('"', '\\"')
        clauses.append(f'(textPayload:"{q}" OR jsonPayload:"{q}")')

    action = param_strings(params, "action")
    if action:
        inner = " OR ".join(f'jsonPayload.connection.disposition="{a.upper()}"' for a in action)
        clauses.append(f"({inner})")

    if not clauses:
        return ""
    return " AND ".join(clauses)
