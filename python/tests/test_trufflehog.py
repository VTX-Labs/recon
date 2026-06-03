"""TruffleHog integration: NDJSON parsing + clear missing-binary handling.
Never invokes the real trufflehog binary."""

from __future__ import annotations

import pytest

from vtx_recon.trufflehog import (
    TruffleHogNotFound,
    find_binary,
    parse_json_stream,
    parse_trufflehog_record,
)


def test_parse_record_maps_fields() -> None:
    aws_key = "AKIA" + "EXAMPLE1234567890"
    finding = parse_trufflehog_record(
        {
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": aws_key,
            "Redacted": "AKIA****",
            "ExtraData": {"account": "1234"},
            "SourceMetadata": {"Data": {"Filesystem": {"file": "config.env"}}},
        }
    )
    assert finding is not None
    assert finding.detector_name == "AWS"
    assert finding.verified is True
    assert finding.raw == aws_key
    assert finding.extra_data == {"account": "1234"}
    assert "config.env" in finding.source


def test_parse_record_ignores_non_results() -> None:
    # Log lines (no DetectorName) are not findings.
    assert parse_trufflehog_record({"level": "info", "msg": "scanning"}) is None
    assert parse_trufflehog_record({}) is None


def test_parse_json_stream_skips_noise() -> None:
    lines = [
        '{"level":"info","msg":"starting"}',  # log line
        "not json at all",  # malformed
        "",  # blank
        '{"DetectorName":"GitHub","Verified":false,"Raw":"ghp_x"}',  # result
        "[1,2,3]",  # non-dict json
    ]
    findings = list(parse_json_stream(lines))
    assert len(findings) == 1
    assert findings[0].detector_name == "GitHub"
    assert findings[0].verified is False


def test_find_binary_missing_raises_with_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vtx_recon.trufflehog.shutil.which", lambda _name: None)
    with pytest.raises(TruffleHogNotFound) as exc:
        find_binary()
    # The error should guide the user to install trufflehog.
    assert "trufflehog" in str(exc.value).lower()


def test_find_binary_returns_path_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vtx_recon.trufflehog.shutil.which", lambda _name: "/usr/bin/trufflehog")
    assert find_binary() == "/usr/bin/trufflehog"
