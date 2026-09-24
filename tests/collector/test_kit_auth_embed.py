"""Tests for embedding connection auth into acquisition kits."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import yaml

from collector.kit.auth_embed import embed_connection_auth
from collector.kit.build import build_kit

ARTIFACTS = Path("artifacts")


def test_embed_gcp_service_account(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    acq: dict = {"cloud": "gcp"}
    sa = {
        "type": "service_account",
        "project_id": "demo-proj",
        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        "client_email": "demo@demo-proj.iam.gserviceaccount.com",
    }
    embed_connection_auth(
        staging,
        {
            "platform": "gcp",
            "auth_method": "service_account",
            "gcp_service_account_json": json.dumps(sa),
            "project": "demo-proj",
        },
        acq,
    )
    assert acq["auth_method"] == "service_account"
    assert acq["gcp_credentials"] == "credentials/gcp-sa.json"
    assert acq["project"] == "demo-proj"
    assert (staging / "credentials" / "gcp-sa.json").is_file()


def test_build_kit_embeds_connection_auth(tmp_path: Path) -> None:
    sa = {
        "type": "service_account",
        "project_id": "demo-proj",
        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        "client_email": "demo@demo-proj.iam.gserviceaccount.com",
    }
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="gcp",
        case_id="CASE-EMBED",
        artifact_names=["scc_findings"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
        connection={
            "platform": "gcp",
            "auth_method": "service_account",
            "gcp_service_account_json": json.dumps(sa),
            "project": "demo-proj",
        },
    )
    with zipfile.ZipFile(out) as zf:
        acq = yaml.safe_load(zf.read("acquisition.yaml"))
        assert acq["gcp_credentials"] == "credentials/gcp-sa.json"
        assert "credentials/gcp-sa.json" in zf.namelist()


def test_build_kit_embeds_aws_profile(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="aws",
        case_id="CASE-AWS",
        artifact_names=["guardduty"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
        connection={
            "platform": "aws",
            "auth_method": "profile",
            "profile_name": "ir-collector",
        },
    )
    with zipfile.ZipFile(out) as zf:
        acq = yaml.safe_load(zf.read("acquisition.yaml"))
    assert acq["aws_profile"] == "ir-collector"
    assert acq["auth_method"] == "profile"


def test_build_kit_embeds_kubernetes_kubeconfig(tmp_path: Path) -> None:
    out = build_kit(
        tmp_path / "kit.zip",
        cloud="kubernetes",
        case_id="CASE-K8S",
        artifact_names=["k8s_events"],
        artifacts_root=ARTIFACTS,
        bundle_wheel=False,
        connection={
            "platform": "kubernetes",
            "auth_method": "kubeconfig",
            "k8s_context": "lab-ctx",
            "kubeconfig_content": "apiVersion: v1\nkind: Config\ncontexts:\n- name: lab-ctx\n  context: {}\n",
        },
    )
    with zipfile.ZipFile(out) as zf:
        acq = yaml.safe_load(zf.read("acquisition.yaml"))
        assert acq["kubeconfig"] == "credentials/kubeconfig.yaml"
        assert acq["k8s_context"] == "lab-ctx"
        assert acq["node_root"] == "/"
        assert "credentials/kubeconfig.yaml" in zf.namelist()
        raw = zf.read("credentials/kubeconfig.yaml").decode()
        assert "lab-ctx" in raw
