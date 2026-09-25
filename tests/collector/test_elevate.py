"""Self-elevation to root for Kubernetes node-plane collection (collector/lib/elevate.py)."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from collector import cli
from collector.lib import elevate


@pytest.fixture
def linux_user(monkeypatch: pytest.MonkeyPatch):
    """A non-root Linux operator at an interactive terminal, with sudo installed."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(elevate.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    for var in (elevate.NO_SUDO_ENV, "KUBECONFIG", "SUDO_UID", "SUDO_USER"):
        monkeypatch.delenv(var, raising=False)
    calls: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(elevate.os, "execv", lambda path, cmd: calls.append((path, cmd)))
    return calls


def test_reexec_builds_sudo_command_without_secrets_in_argv(linux_user, monkeypatch, tmp_path):
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "kubeconfig"))
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "super-secret")
    elevate.reexec_with_sudo(["run", "Test-K8S.kit"], reason="node files")

    [(path, cmd)] = linux_user
    assert path == "/usr/bin/sudo"
    assert cmd[:3] == ["/usr/bin/sudo", "--", "env"]
    assert cmd[-5:] == [sys.executable, "-m", "collector", "run", "Test-K8S.kit"]
    assert not any("super-secret" in part for part in cmd), "secrets must never be in argv"

    env_file = Path(cmd[3].split("=", 1)[1])
    try:
        assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
        env = json.loads(env_file.read_text())
        assert env["KUBECONFIG"] == str(tmp_path / "kubeconfig")
        assert env["AWS_SECRET_ACCESS_KEY"] == "super-secret"
    finally:
        env_file.unlink(missing_ok=True)


@pytest.mark.parametrize(
    "setup",
    [
        lambda mp: mp.setattr(os, "geteuid", lambda: 0, raising=False),  # already root
        lambda mp: mp.setattr(sys, "platform", "darwin"),  # node files only exist on Linux
        lambda mp: mp.setenv(elevate.NO_SUDO_ENV, "1"),  # opted out
        lambda mp: mp.setattr(elevate.shutil, "which", lambda name: None),  # no sudo
    ],
)
def test_no_reexec_when_not_needed_or_not_possible(linux_user, monkeypatch, setup):
    setup(monkeypatch)
    elevate.reexec_with_sudo(["run", "k.kit"], reason="node files")
    assert linux_user == []


def test_no_prompt_without_a_terminal(linux_user, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(elevate, "_sudo_allowed_without_prompt", lambda sudo: False)
    elevate.reexec_with_sudo(["run", "k.kit"], reason="node files")
    assert linux_user == []


def test_elevated_process_loads_and_deletes_env_file(monkeypatch, tmp_path):
    env_file = tmp_path / "env.json"
    env_file.write_text(json.dumps({"KUBECONFIG": "/home/omar/.kube/config", "VENTRA_X": "1"}))
    monkeypatch.setenv(elevate.ENV_FILE_ENV, str(env_file))
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.delenv("KUBECONFIG", raising=False)
    monkeypatch.delenv("VENTRA_X", raising=False)

    elevate.load_passthrough_env()

    assert os.environ["KUBECONFIG"] == "/home/omar/.kube/config"
    assert os.environ["VENTRA_X"] == "1"
    assert not env_file.exists()
    assert elevate.ENV_FILE_ENV not in os.environ


def test_invoking_user_is_the_sudo_caller(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("SUDO_USER", "omar")
    assert elevate.invoking_user() == "omar"


def test_hand_back_only_touches_root_files_created_during_the_run(monkeypatch, tmp_path):
    new_root_file = tmp_path / "package.tar.zst"
    old_root_file = tmp_path / "preexisting.conf"
    user_file = tmp_path / "mine.txt"
    for f in (new_root_file, old_root_file, user_file):
        f.write_text("x")

    now = time.time()
    fake = {
        new_root_file: SimpleNamespace(st_uid=0, st_mtime=now),
        old_root_file: SimpleNamespace(st_uid=0, st_mtime=now - 86400),
        user_file: SimpleNamespace(st_uid=1000, st_mtime=now),
        tmp_path: SimpleNamespace(st_uid=1000, st_mtime=now),
    }
    real_lstat = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda self: fake.get(self) or real_lstat(self))
    chowned: list[Path] = []
    monkeypatch.setattr(elevate.os, "lchown", lambda p, uid, gid: chowned.append(Path(p)))
    monkeypatch.setattr(elevate, "_started_at", now - 5)
    monkeypatch.setattr(elevate, "_handback_roots", [tmp_path])

    elevate._chown_created(1000, 1000)

    assert chowned == [new_root_file]


def test_node_plane_kit_triggers_elevation(monkeypatch):
    calls = []
    monkeypatch.setattr(elevate, "is_root", lambda: False)
    monkeypatch.setattr(elevate, "reexec_with_sudo", lambda argv, **kw: calls.append((argv, kw)))
    args = SimpleNamespace(_argv=["run", "k.kit"], no_sudo=False)

    cli._elevate_for_node_plane(args, ["k8s_events", "k8s_rbac"], out="evidence")
    assert calls == [], "API-plane-only runs never need root"

    cli._elevate_for_node_plane(args, ["k8s_events", "k8s_apiserver_audit"], out="evidence")
    assert calls and calls[0][0] == ["run", "k.kit"]
    assert calls[0][1]["disabled"] is False
