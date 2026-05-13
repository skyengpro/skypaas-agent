"""HMAC-signed login token, the cryptographic primitive of PR-C.

A token is a short string the SkyEngPro Cloud backend mints when an
operator clicks "Login as Admin" in the dashboard. It carries:

  - the Frappe user to log in as (almost always ``Administrator``)
  - the target site (so a token minted for tenant A can't unlock tenant B)
  - an absolute expiry (60 seconds in the future by default)

The agent on the tenant side verifies the HMAC-SHA256 signature with a
secret shared between the control plane and that one tenant (per-tenant
secret, NOT global — compromise of one tenant doesn't bleed across).

Wire format:

    <base64url(json_payload)>.<hex(hmac_sha256(secret, payload))>

We deliberately avoid the full JWT library — the agent must run inside
a Frappe bench with no extra runtime deps. stdlib hmac + base64 is
all we need.
"""

from __future__ import annotations

import base64
import hmac
import json
import time
from dataclasses import dataclass
from hashlib import sha256

DEFAULT_TTL_SECONDS = 60
MAX_TTL_SECONDS = 300  # cap so a misconfigured caller can't mint an hour-long token


@dataclass(frozen=True)
class LoginPayload:
    user: str
    site: str
    exp: int  # unix timestamp seconds

    def to_dict(self) -> dict:
        return {"user": self.user, "site": self.site, "exp": self.exp}


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def sign(payload: LoginPayload, secret: bytes) -> str:
    """Build a wire-format token.

    `secret` is the per-tenant HMAC key, expected ≥32 random bytes.
    """
    if len(secret) < 16:
        raise ValueError("agent HMAC secret too short (≥16 bytes required)")
    raw = json.dumps(payload.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")
    p_b64 = _b64url(raw)
    mac = hmac.new(secret, raw, sha256).hexdigest()
    return f"{p_b64}.{mac}"


class TokenError(ValueError):
    """Raised when verify() rejects a token. The .reason attribute carries
    a stable enum-like string for audit logs; the human-friendly message
    is the exception text."""

    def __init__(self, reason: str, message: str | None = None) -> None:
        super().__init__(message or reason)
        self.reason = reason


def verify(
    token: str, secret: bytes, expected_site: str, *, now: int | None = None
) -> LoginPayload:
    """Validate a token's signature, expiry, and site binding.

    Raises TokenError(reason=...) with one of:
      - "malformed"      : wrong format / can't decode
      - "bad_signature"  : HMAC mismatch (constant-time compared)
      - "expired"        : exp ≤ now
      - "wrong_site"     : payload.site != expected_site
      - "too_long_ttl"   : exp - now > MAX_TTL_SECONDS (defensive)

    Returns the verified LoginPayload on success.
    """
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenError("malformed", "token must be '<payload>.<mac>'")
    p_b64, mac_hex = token.split(".", 1)

    try:
        raw = _b64url_decode(p_b64)
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise TokenError("malformed", str(e)) from e

    expected_mac = hmac.new(secret, raw, sha256).hexdigest()
    if not hmac.compare_digest(mac_hex, expected_mac):
        raise TokenError("bad_signature")

    # Only AFTER signature passes do we trust the payload contents.
    if not isinstance(body, dict):
        raise TokenError("malformed", "payload must be an object")
    try:
        payload = LoginPayload(user=str(body["user"]), site=str(body["site"]), exp=int(body["exp"]))
    except (KeyError, TypeError, ValueError) as e:
        raise TokenError("malformed", f"missing or wrong-type field: {e}") from e

    now = now if now is not None else int(time.time())
    if payload.exp <= now:
        raise TokenError("expired")
    if payload.exp - now > MAX_TTL_SECONDS:
        # Caller minted a token good for too long — refuse so a token
        # can't sit in someone's clipboard for an hour and still work.
        raise TokenError("too_long_ttl")
    if payload.site != expected_site:
        raise TokenError(
            "wrong_site", f"token bound to {payload.site!r}, this site is {expected_site!r}"
        )

    return payload
