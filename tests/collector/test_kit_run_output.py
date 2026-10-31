"""``ventra run`` terminal output and the required output folder."""

from __future__ import annotations

import argparse
import io
import json
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from rich.console import Console

from collector import cli
from collector.kit import run as kit_run
from collector.kit.run_view import RUN_LOG_NAME, KitRunView, build_table
from collector.lib.models import GapReason, SourceResult, SourceStatus

RAW_ERROR = (
    "An error occurred (InvalidClientTokenId) when calling the ListAccountAliases operation: "
    "The security token included in the request is invalid."
)


def _console() -> Console:
    return Console(file=io.StringIO(), width=80, force_terminal=False, color_system=None, record=True)


def _write_kit(tmp_path: Path, *, hours: float = 36) -> Path:
    staging = tmp_path / "staging"
    (staging / "credentials").mkdir(parents=True)
    (staging / "acquisition.yaml").write_text("case_id: CASE-OUT\ncloud: aws\nartifacts: []\n")
    (staging / "credentials" / "aws.json").write_text(
        json.dumps({"aws_access_key_id": "AK", "aws_secret_access_key": "SK", "aws_session_token": "T"})
    )
    now = datetime.now(timezone.utc)
    exp = (now + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (staging / "kit.json").write_text(
        json.dumps(
            {
                "format": "ventra.kit",
                "kit_id": "kit-out",
                "kit_name": "Prod IR",
                "case_id": "CASE-OUT",
                "cloud": "aws",
                "ventra_version": "0.0.0",
                "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": exp,
                "collectors": ["cloudtrail", "iam"],
                "credential": {
                    "provider": "aws",
                    "kind": "sts_session",
                    "expires_at": exp,
                    "limited_by": "credential",
                    "kit_ttl_seconds": 7 * 24 * 3600,
                },
            }
        )
    )
    out = tmp_path / "prod-ir.kit"
    with zipfile.ZipFile(out, "w") as zf:
        for path in staging.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(staging).as_posix())
    return out


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "VENTRA_ARTIFACTS_ROOT",
    ):
        monkeypatch.setenv(key, "")
        monkeypatch.delenv(key)


def _stub_collection(monkeypatch: pytest.MonkeyPatch, *, raise_exc: Exception | None = None) -> None:
    def _fake(*, out_dir: Path, view: KitRunView, **_: Any):
        if raise_exc is not None:
            raise raise_exc
        view.begin_run("123456789012", ["us-east-1"], "CASE-OUT", ["cloudtrail", "iam"])
        view.start("cloudtrail")
        view.finish(
            "cloudtrail", SourceResult(name="cloudtrail", status=SourceStatus.COLLECTED, record_count=48213)
        )
        view.start("iam")
        view.finish(
            "iam",
            SourceResult(
                name="iam",
                status=SourceStatus.ERRORED,
                record_count=0,
                gaps=[("iam", GapReason.COLLECTOR_ERROR, RAW_ERROR)],
            ),
        )
        view.finalize()
        pkg = out_dir / "case-CASE-OUT.tar.zst"
        pkg.write_bytes(b"sealed")
        return SimpleNamespace(path=pkg), view.rows()

    monkeypatch.setattr(kit_run, "_execute_collection", _fake)


def test_table_has_one_plain_row_per_collector() -> None:
    view = KitRunView(_console())
    view.begin_run("acct", [], "C", ["cloudtrail", "guardduty", "iam", "s3"])
    view.start("cloudtrail")
    view.finish(
        "cloudtrail", SourceResult(name="cloudtrail", status=SourceStatus.COLLECTED, record_count=1234)
    )
    view.start("iam")
    view.finish(
        "iam",
        SourceResult(
            name="iam", status=SourceStatus.ERRORED, gaps=[("iam", GapReason.COLLECTOR_ERROR, RAW_ERROR)]
        ),
    )
    view.start("guardduty")

    console = _console()
    console.print(build_table(view.matrix))
    text = console.export_text()
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    assert lines[0].split() == ["Collector", "Records", "Status"]
    rows = {line.split()[0]: line.split()[1:] for line in lines[2:]}
    assert rows == {
        "cloudtrail": ["1,234", "Succeeded"],
        "guardduty": ["Running"],
        "iam": ["-", "Failed"],
        "s3": ["Pending"],
    }
    assert "InvalidClientTokenId" not in text
    assert "Severity" not in text
    assert all(len(line) <= 80 for line in text.splitlines())


def test_plain_rows_when_not_a_terminal() -> None:
    console = _console()
    view = KitRunView(console)
    view.begin_run("acct", [], "C", ["cloudtrail", "iam"])
    view.start("cloudtrail")
    view.finish("cloudtrail", SourceResult(name="cloudtrail", status=SourceStatus.COLLECTED, record_count=5))
    view.finalize()
    text = console.export_text()
    assert "Collector" in text and "Succeeded" in text
    assert view.rows()[1]["status"] == "pending"


def test_run_output_is_short_and_errors_go_to_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    _stub_collection(monkeypatch)
    console = _console()
    out = tmp_path / "evidence"
    result = kit_run.run_kit_file(_write_kit(tmp_path), out_dir=out, console=console)
    text = console.export_text()

    assert result.success
    for expected in (
        "Ventra · Prod IR",
        "Case      CASE-OUT",
        "Cloud     AWS",
        f"Output    {out.resolve()}",
        "Set by the AWS credential's lifetime; the kit itself allows 7 days.",
        "Done. 1 succeeded, 1 failed · 48,213 records",
        f"Details   {out.resolve() / RUN_LOG_NAME}",
    ):
        assert expected in text, expected
    for jargon in ("InvalidClientTokenId", "kit_id", "operator", "Severity", "pending", "version"):
        assert jargon not in text, jargon

    log = (out / RUN_LOG_NAME).read_text()
    assert RAW_ERROR in log
    assert "iam: Failed" in log
    custody = json.loads((out / "cli_run.json").read_text())
    assert custody["collectors_detail"][1]["detail"] == RAW_ERROR


def test_clean_run_has_no_details_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    def _fake(*, out_dir: Path, view: KitRunView, **_: Any):
        view.begin_run("a", [], "C", ["cloudtrail"])
        view.finish(
            "cloudtrail", SourceResult(name="cloudtrail", status=SourceStatus.COLLECTED, record_count=1)
        )
        view.finalize()
        return SimpleNamespace(path=out_dir / "p.tar.zst"), view.rows()

    monkeypatch.setattr(kit_run, "_execute_collection", _fake)
    console = _console()
    kit_run.run_kit_file(_write_kit(tmp_path), out_dir=tmp_path / "ev", console=console)
    text = console.export_text()
    assert "Done. 1 succeeded · 1 records" in text
    assert "Details" not in text


def test_crash_keeps_traceback_out_of_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    _stub_collection(monkeypatch, raise_exc=RuntimeError("boom from botocore internals"))
    console = _console()
    out = tmp_path / "ev"
    result = kit_run.run_kit_file(_write_kit(tmp_path), out_dir=out, console=console)
    text = console.export_text()
    assert not result.success
    assert "Run failed. Collection stopped unexpectedly." in text
    assert "boom" not in text and "Traceback" not in text
    assert f"Details   {out.resolve() / RUN_LOG_NAME}" in text
    log = (out / RUN_LOG_NAME).read_text()
    assert "Traceback" in log and "boom from botocore internals" in log


def test_rejected_credentials_get_a_plain_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_env: None
) -> None:
    _stub_collection(monkeypatch, raise_exc=RuntimeError(RAW_ERROR))
    console = _console()
    kit_run.run_kit_file(_write_kit(tmp_path), out_dir=tmp_path / "ev", console=console)
    text = " ".join(console.export_text().split())
    assert "Run failed. AWS rejected the credentials in this kit." in text
    assert "InvalidClientTokenId" not in text


def test_expired_kit_says_so_plainly(tmp_path: Path, clean_env: None) -> None:
    console = _console()
    result = kit_run.run_kit_file(_write_kit(tmp_path, hours=-1), out_dir=tmp_path / "ev", console=console)
    text = " ".join(console.export_text().split())
    assert not result.success
    assert "Run failed. This kit expired at" in text
    assert "Download a fresh kit from Acquire" in text


# --- --out is required -------------------------------------------------------------------


def _args(kit: Path, out: str = "") -> argparse.Namespace:
    return argparse.Namespace(kit=str(kit), out=out, no_sudo=True, _argv=["run", str(kit)])


def test_parser_has_no_out_default() -> None:
    args = cli.build_parser().parse_args(["run", "x.kit"])
    assert args.out == ""


def test_no_out_without_terminal_fails_with_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    called: list[Any] = []
    monkeypatch.setattr(kit_run, "run_kit_file", lambda *a, **k: called.append(a))
    monkeypatch.chdir(tmp_path)

    assert cli._run_kit_file(_args(tmp_path / "prod.kit")) == 2
    err = capsys.readouterr().err
    assert "--out" in err
    assert f"ventra run {tmp_path / 'prod.kit'} --out ./evidence" in err
    assert called == []
    assert not (tmp_path / "evidence").exists()


def test_no_out_on_terminal_prompts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    chosen = tmp_path / "case-evidence"
    monkeypatch.setattr(cli, "_prompt_out_dir", lambda: chosen)
    seen: dict[str, Any] = {}

    def _run(kit: Path, *, out_dir: Path) -> Any:
        seen["out"] = out_dir
        return SimpleNamespace(success=True, delivery_error="")

    monkeypatch.setattr(kit_run, "run_kit_file", _run)
    args = _args(tmp_path / "prod.kit")
    assert cli._run_kit_file(args) == 0
    assert seen["out"] == chosen
    # A sudo re-run reuses the answer instead of asking again.
    assert args._argv[-2:] == ["--out", str(chosen)]


def _prompt(answers: list[str]) -> tuple[Path | None, list[str]]:
    said: list[str] = []
    it = iter(answers)

    def _input(prompt: str) -> str:
        said.append(prompt)
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None

    return cli._prompt_out_dir(input_fn=_input, print_fn=said.append), said


def test_prompt_creates_missing_folder_after_confirming(tmp_path: Path) -> None:
    target = tmp_path / "new" / "evidence"
    path, said = _prompt([str(target), "y"])
    assert path == target.resolve()
    assert target.is_dir()
    assert any("does not exist. Create it?" in s for s in said)


def test_prompt_reasks_on_empty_file_and_declined_create(tmp_path: Path) -> None:
    a_file = tmp_path / "file.txt"
    a_file.write_text("x")
    existing = tmp_path / "existing"
    existing.mkdir()
    path, said = _prompt(["", str(a_file), str(tmp_path / "nope"), "n", str(existing)])
    assert path == existing.resolve()
    assert "  Enter a folder path." in said
    assert f"  {a_file.resolve()} exists and is not a folder." in said
    assert not (tmp_path / "nope").exists()


def test_prompt_eof_cancels(tmp_path: Path) -> None:
    path, _ = _prompt([])
    assert path is None


def test_out_pointing_at_file_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    a_file = tmp_path / "f"
    a_file.write_text("x")
    monkeypatch.setattr(kit_run, "run_kit_file", lambda *a, **k: pytest.fail("should not run"))
    assert cli._run_kit_file(_args(tmp_path / "k.kit", out=str(a_file))) == 2
    assert "is not a folder" in capsys.readouterr().err
