"""Secrets must never appear raw in output or evidence bundles."""

from __future__ import annotations

from vtx_recon.redact import redact, redact_mapping


def test_redact_keeps_short_prefix_and_masks_rest() -> None:
    out = redact("sk-live-abcdef1234567890")
    assert out.startswith("sk-l")
    assert "abcdef" not in out
    assert set(out[4:]) == {"*"}


def test_redact_clamps_mask_length() -> None:
    # A very long secret must not reveal its true length.
    out = redact("A" * 500)
    assert len(out) <= 4 + 8  # prefix + capped mask


def test_redact_fully_masks_very_short_secret() -> None:
    # Secrets at or below the prefix length are fully masked (no prefix shown).
    assert redact("abc") == "***"  # 3 chars <= prefix(4)
    assert redact("abcd") == "****"  # 4 chars == prefix(4)
    # Just over the prefix: shows the prefix + a single mask char.
    assert redact("short") == "shor*"  # 5 chars > prefix(4)


def test_redact_handles_empty_and_none() -> None:
    assert redact("") == "<empty>"
    assert redact(None) == "<none>"


def test_redact_bytes() -> None:
    assert redact(b"ghp_secrettoken").startswith("ghp_")


def test_redact_mapping_walks_nested_secret_keys() -> None:
    data = {
        "DetectorName": "AWS",
        "Raw": "AKIA" + "EXAMPLE1234567890",
        "ExtraData": {"token": "xoxb-very-secret", "account": "acme"},
        "list": [{"password": "hunter2hunter2"}],
    }
    out = redact_mapping(data)
    assert out["DetectorName"] == "AWS"  # non-secret untouched
    assert "AKIA" + "EXAMPLE" not in str(out["Raw"])
    assert "very-secret" not in str(out["ExtraData"]["token"])  # type: ignore[index]
    assert out["ExtraData"]["account"] == "acme"  # type: ignore[index]
    assert "hunter2" not in str(out["list"][0]["password"])  # type: ignore[index]


def test_redact_mapping_is_case_insensitive_on_keys() -> None:
    out = redact_mapping({"API_KEY": "secretvalue123"})
    assert "secretvalue" not in str(out["API_KEY"])
