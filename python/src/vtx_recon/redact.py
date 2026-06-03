"""Secret redaction — used everywhere a credential might be printed or stored.

Rule: a raw secret is **never** persisted to disk or emitted in output.
Every secret is reduced to a stable ``prefix + mask`` form that is enough
to correlate a finding with a leak report without disclosing the secret
itself. The transform is one-way and deterministic.
"""

from __future__ import annotations

__all__ = ["redact", "redact_mapping"]

# How many leading characters of a secret we keep in the clear. Enough to
# recognise a provider prefix (e.g. "sk-", "AKIA", "xoxb-", "ghp_") without
# exposing meaningful entropy.
_DEFAULT_PREFIX = 4
_MASK_CHAR = "*"
# Cap the rendered mask so a long token does not leak its exact length.
_MAX_MASK = 8


def redact(secret: str | bytes | None, *, prefix: int = _DEFAULT_PREFIX) -> str:
    """Reduce a secret to ``prefix + mask``.

    Examples:
        >>> redact("sk-live-abcdef1234567890")
        'sk-l********'
        >>> redact("short")
        '*****'
        >>> redact("")
        '<empty>'
        >>> redact(None)
        '<none>'

    The mask length is clamped (``_MAX_MASK``) so the output does not reveal
    the true length of long secrets. Short secrets (shorter than ``prefix``)
    are fully masked so no meaningful portion is shown.
    """
    if secret is None:
        return "<none>"
    if isinstance(secret, bytes):
        secret = secret.decode("utf-8", errors="replace")
    if secret == "":
        return "<empty>"

    n = len(secret)
    if n <= prefix:
        # Too short to safely reveal a prefix; mask the whole thing.
        return _MASK_CHAR * n

    visible = secret[:prefix]
    masked = min(n - prefix, _MAX_MASK)
    return f"{visible}{_MASK_CHAR * masked}"


def redact_mapping(
    data: dict[str, object],
    *,
    secret_keys: frozenset[str] = frozenset(
        {
            "raw",
            "secret",
            "key",
            "api_key",
            "token",
            "password",
            "client_secret",
            "private_key",
            "aws_secret_access_key",
        }
    ),
    prefix: int = _DEFAULT_PREFIX,
) -> dict[str, object]:
    """Return a deep copy of ``data`` with any secret-valued keys redacted.

    Keys are matched case-insensitively against ``secret_keys``. Nested
    dicts and lists are walked so a secret buried in ``ExtraData`` is caught
    too. Use this before serialising anything to an evidence bundle.
    """

    def _walk(value: object, *, redact_value: bool) -> object:
        if isinstance(value, dict):
            return {k: _walk(v, redact_value=k.lower() in secret_keys) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(item, redact_value=redact_value) for item in value]
        if redact_value and isinstance(value, (str, bytes)):
            return redact(value, prefix=prefix)
        return value

    result = _walk(data, redact_value=False)
    assert isinstance(result, dict)
    return result
