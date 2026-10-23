"""`ventra-verify` reports unreadable input as a one-line error, and is honest about --key."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "fixtures"))

from generate_demo_case import generate

from ventra_ingester.cli import verify_main


@pytest.mark.parametrize("content", [b"junk\n", None])
def test_unreadable_package_is_a_clean_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: bytes | None
) -> None:
    pkg = tmp_path / "bad.tar.zst"
    if content is not None:
        pkg.write_bytes(content)

    assert verify_main([str(pkg)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: cannot read")
    assert "Traceback" not in err


def test_key_flag_says_it_was_not_used(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pkg = generate(tmp_path)

    assert verify_main([str(pkg), "--key", "release.pub"]) == 0
    assert "--key is not implemented yet" in capsys.readouterr().out
