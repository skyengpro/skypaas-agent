"""HMAC-signed tokens — the cryptographic primitive shared by every
control-plane → agent call.

Two payload shapes today:

  - ``LoginPayload`` (PR-C, shipped 0.1.0) — minted when the operator
    clicks "Login as Admin". Carries ``{user, site, exp}``. Consumed by
    ``api.login_via_token`` which calls ``login_manager.login_as``.

  - ``OperationPayload`` (PR #1A, Phase 2 ADR-0017) — minted when the
    control plane calls any non-login endpoint on the agent (list
    sites, create site, backup, etc.). Carries ``{op, site, exp}``.
    Consumed by ``api.<op_endpoint>`` after verifying that the token's
    ``op`` matches the endpoint being called.

Both payloads share the same HMAC secret (per-tenant, loaded from
``site_config.json:skypaas_agent_hmac_secret``) and the same wire
format. They are NOT interchangeable: a LoginPayload cannot unlock a
site-CRUD endpoint and vice versa. The verifier checks the payload
shape against the expected one and rejects mismatches.

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


@dataclass(frozen=True)
class OperationPayload:
    """Authorises a single agent operation call.

    `op` is the operation kind (e.g. ``list_sites``, ``create_site``).
    `site` scopes the call to one Frappe site — even when the operation
    is bench-wide (``list_sites``), the token still binds to one site
    so a token minted for tenant A can't unlock the same operation on
    tenant B's bench if their HMAC secrets ever happen to collide.
    """

    op: str
    site: str
    exp: int  # unix timestamp seconds

    def to_dict(self) -> dict:
        return {"op": self.op, "site": self.site, "exp": self.exp}


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def sign(payload: LoginPayload | OperationPayload, secret: bytes) -> str:
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


def verify_operation(
    token: str,
    secret: bytes,
    expected_site: str,
    expected_op: str,
    *,
    now: int | None = None,
) -> OperationPayload:
    """Validate an operation token.

    Mirrors :func:`verify` but for ``OperationPayload``. Extra check:
    the payload's ``op`` field must match ``expected_op`` — a token
    minted for ``op=list_sites`` cannot unlock the ``create_site``
    endpoint.

    Raises ``TokenError(reason=…)`` with one of the verify() reasons
    plus:

      - ``"wrong_op"`` : payload.op != expected_op
      - ``"wrong_shape"`` : payload lacks the OperationPayload fields
        (e.g. a LoginPayload was passed where an OperationPayload was
        expected — same wire format, different fields).
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

    if not isinstance(body, dict):
        raise TokenError("malformed", "payload must be an object")

    # Wrong-shape detection comes BEFORE field reads so a LoginPayload
    # ({user, site, exp}) is cleanly rejected with reason="wrong_shape"
    # rather than KeyError-styled "malformed: 'op'".
    if "op" not in body or "user" in body:
        raise TokenError(
            "wrong_shape",
            "expected OperationPayload {op, site, exp}; got something else",
        )

    try:
        payload = OperationPayload(
            op=str(body["op"]), site=str(body["site"]), exp=int(body["exp"])
        )
    except (KeyError, TypeError, ValueError) as e:
        raise TokenError("malformed", f"missing or wrong-type field: {e}") from e

    now = now if now is not None else int(time.time())
    if payload.exp <= now:
        raise TokenError("expired")
    if payload.exp - now > MAX_TTL_SECONDS:
        raise TokenError("too_long_ttl")
    if payload.site != expected_site:
        raise TokenError(
            "wrong_site", f"token bound to {payload.site!r}, this site is {expected_site!r}"
        )
    if payload.op != expected_op:
        raise TokenError(
            "wrong_op", f"token authorises {payload.op!r}, endpoint is {expected_op!r}"
        )

    return payload
