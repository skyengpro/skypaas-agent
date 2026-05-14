"""Unit tests for the HMAC-signed token primitives."""

from __future__ import annotations

import secrets
import time

import pytest
from skypaas_agent.tokens import (
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    LoginPayload,
    OperationPayload,
    TokenError,
    sign,
    verify,
    verify_operation,
)

# A 32-byte test secret (NOT a real one). Reused across tests for
# determinism — production secrets are generated per-tenant by the
# control plane.
SECRET_A = bytes.fromhex("a" * 64)
SECRET_B = bytes.fromhex("b" * 64)


def _fresh_payload(site: str = "tenant.example.com", user: str = "Administrator") -> LoginPayload:
    return LoginPayload(user=user, site=site, exp=int(time.time()) + DEFAULT_TTL_SECONDS)


class TestSign:
    def test_round_trip(self) -> None:
        payload = _fresh_payload()
        token = sign(payload, SECRET_A)
        verified = verify(token, SECRET_A, expected_site=payload.site)
        assert verified.user == payload.user
        assert verified.site == payload.site
        assert verified.exp == payload.exp

    def test_two_tokens_for_same_payload_are_identical(self) -> None:
        """HMAC is deterministic; no nonce in our format. Same input ⇒
        same token. This is intentional — short TTL is what prevents
        replay, not unpredictability."""
        p = _fresh_payload()
        assert sign(p, SECRET_A) == sign(p, SECRET_A)

    def test_short_secret_rejected_at_sign_time(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            sign(_fresh_payload(), b"x")


class TestVerifyRejection:
    def test_malformed_token_no_dot(self) -> None:
        with pytest.raises(TokenError) as ei:
            verify("not-a-token-at-all", SECRET_A, expected_site="x")
        assert ei.value.reason == "malformed"

    def test_malformed_token_bad_base64(self) -> None:
        with pytest.raises(TokenError) as ei:
            verify("!!!.deadbeef", SECRET_A, expected_site="x")
        assert ei.value.reason == "malformed"

    def test_bad_signature(self) -> None:
        token = sign(_fresh_payload(), SECRET_A)
        with pytest.raises(TokenError) as ei:
            verify(token, SECRET_B, expected_site=_fresh_payload().site)
        assert ei.value.reason == "bad_signature"

    def test_signature_check_is_constant_time(self) -> None:
        """Sanity: the verify path uses hmac.compare_digest. We can't
        instrument timing here, but we CAN confirm the call site exists
        — any future refactor that drops it will break this test."""
        import skypaas_agent.tokens as tokens_module

        src = (tokens_module.__file__ or "").replace(".pyc", ".py")
        with open(src) as f:
            assert "compare_digest" in f.read()

    def test_expired_token_rejected(self) -> None:
        past_payload = LoginPayload(
            user="Administrator", site="tenant.example.com", exp=int(time.time()) - 5
        )
        token = sign(past_payload, SECRET_A)
        with pytest.raises(TokenError) as ei:
            verify(token, SECRET_A, expected_site=past_payload.site)
        assert ei.value.reason == "expired"

    def test_too_long_ttl_rejected(self) -> None:
        """A token minted with a 1-hour TTL must still be rejected even
        if signed correctly — defends against a misconfigured control
        plane minting long-lived tokens that could sit in someone's
        clipboard."""
        far_future = LoginPayload(
            user="Administrator",
            site="tenant.example.com",
            exp=int(time.time()) + MAX_TTL_SECONDS + 60,
        )
        token = sign(far_future, SECRET_A)
        with pytest.raises(TokenError) as ei:
            verify(token, SECRET_A, expected_site=far_future.site)
        assert ei.value.reason == "too_long_ttl"

    def test_wrong_site_binding(self) -> None:
        """A token minted for tenant A must NOT validate against tenant
        B's site, even if both share the same secret (which they
        shouldn't, but defense in depth)."""
        payload = _fresh_payload(site="alpha.example.com")
        token = sign(payload, SECRET_A)
        with pytest.raises(TokenError) as ei:
            verify(token, SECRET_A, expected_site="beta.example.com")
        assert ei.value.reason == "wrong_site"


class TestVerifyAccept:
    def test_token_at_default_ttl_accepts(self) -> None:
        payload = _fresh_payload()
        token = sign(payload, SECRET_A)
        verified = verify(token, SECRET_A, expected_site=payload.site)
        assert verified.user == "Administrator"

    def test_clock_skew_grace_does_not_exist(self) -> None:
        """We don't grant clock-skew grace. If the control plane and the
        tenant clock disagree by 10s, a 60s token gives 50s of usable
        window. This is acceptable for our deployment topology
        (same cluster, NTP-synced) and removes a class of bugs."""
        now = int(time.time())
        token = sign(LoginPayload(user="x", site="t", exp=now + 30), SECRET_A)
        # 31s into the future — token has expired
        with pytest.raises(TokenError) as ei:
            verify(token, SECRET_A, expected_site="t", now=now + 31)
        assert ei.value.reason == "expired"


class TestSecretIsolation:
    """A token minted for tenant A with secret-A must not validate
    against tenant B (different secret, different site, both)."""

    def test_secret_a_does_not_unlock_secret_b(self) -> None:
        token_a = sign(_fresh_payload(site="a.example.com"), SECRET_A)
        with pytest.raises(TokenError):
            verify(token_a, SECRET_B, expected_site="a.example.com")

    def test_random_secret_round_trip(self) -> None:
        """The real control plane generates per-tenant secrets via
        secrets.token_bytes(32). Verify that pattern works end-to-end."""
        secret = secrets.token_bytes(32)
        payload = _fresh_payload(site="random-tenant.test")
        token = sign(payload, secret)
        assert verify(token, secret, expected_site=payload.site).user == "Administrator"


# ---------- Phase 2 (PR #1A): OperationPayload ----------


def _fresh_op_payload(op: str = "list_sites", site: str = "tenant.example.com") -> OperationPayload:
    return OperationPayload(op=op, site=site, exp=int(time.time()) + DEFAULT_TTL_SECONDS)


class TestOperationPayloadRoundTrip:
    def test_sign_and_verify(self) -> None:
        payload = _fresh_op_payload()
        token = sign(payload, SECRET_A)
        verified = verify_operation(
            token, SECRET_A, expected_site=payload.site, expected_op=payload.op
        )
        assert verified.op == payload.op
        assert verified.site == payload.site
        assert verified.exp == payload.exp

    def test_dataclass_is_frozen(self) -> None:
        p = _fresh_op_payload()
        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            p.op = "create_site"  # type: ignore[misc]


class TestOperationRejection:
    def test_wrong_op_rejected(self) -> None:
        """A token minted for op=list_sites must NOT unlock op=create_site
        even with otherwise-valid signature, site, and expiry. This is
        the same cross-binding semantic as the confirm-token pattern in
        the control plane."""
        token = sign(_fresh_op_payload(op="list_sites"), SECRET_A)
        with pytest.raises(TokenError) as ei:
            verify_operation(
                token, SECRET_A, expected_site="tenant.example.com", expected_op="create_site"
            )
        assert ei.value.reason == "wrong_op"

    def test_wrong_site_rejected(self) -> None:
        token = sign(_fresh_op_payload(site="alpha.example.com"), SECRET_A)
        with pytest.raises(TokenError) as ei:
            verify_operation(
                token, SECRET_A, expected_site="beta.example.com", expected_op="list_sites"
            )
        assert ei.value.reason == "wrong_site"

    def test_bad_signature_rejected(self) -> None:
        token = sign(_fresh_op_payload(), SECRET_A)
        with pytest.raises(TokenError) as ei:
            verify_operation(
                token, SECRET_B, expected_site="tenant.example.com", expected_op="list_sites"
            )
        assert ei.value.reason == "bad_signature"

    def test_expired_token_rejected(self) -> None:
        payload = OperationPayload(op="list_sites", site="t.example.com", exp=int(time.time()) - 5)
        token = sign(payload, SECRET_A)
        with pytest.raises(TokenError) as ei:
            verify_operation(
                token, SECRET_A, expected_site="t.example.com", expected_op="list_sites"
            )
        assert ei.value.reason == "expired"

    def test_too_long_ttl_rejected(self) -> None:
        far_future = OperationPayload(
            op="list_sites",
            site="t.example.com",
            exp=int(time.time()) + MAX_TTL_SECONDS + 60,
        )
        token = sign(far_future, SECRET_A)
        with pytest.raises(TokenError) as ei:
            verify_operation(
                token, SECRET_A, expected_site="t.example.com", expected_op="list_sites"
            )
        assert ei.value.reason == "too_long_ttl"

    def test_malformed_token_rejected(self) -> None:
        with pytest.raises(TokenError) as ei:
            verify_operation(
                "not-a-token-at-all", SECRET_A, expected_site="x", expected_op="list_sites"
            )
        assert ei.value.reason == "malformed"


class TestPayloadShapeIsolation:
    """LoginPayload and OperationPayload share the wire format. They
    are NOT interchangeable. A LoginPayload token must NOT validate as
    an OperationPayload and vice versa — even when the signature is
    correct, site matches, expiry hasn't elapsed.

    This is the security-property defense: an operator's
    Login-as-Admin token cannot be replayed against a site-CRUD
    endpoint to gain bench-level mutation power."""

    def test_login_payload_rejected_by_verify_operation(self) -> None:
        login_token = sign(
            LoginPayload(
                user="Administrator", site="t.example.com", exp=int(time.time()) + 30
            ),
            SECRET_A,
        )
        with pytest.raises(TokenError) as ei:
            verify_operation(
                login_token,
                SECRET_A,
                expected_site="t.example.com",
                expected_op="list_sites",
            )
        assert ei.value.reason == "wrong_shape"

    def test_operation_payload_rejected_by_verify(self) -> None:
        op_token = sign(
            OperationPayload(op="list_sites", site="t.example.com", exp=int(time.time()) + 30),
            SECRET_A,
        )
        # `verify` (LoginPayload) lacks an explicit wrong_shape check —
        # it falls through to "malformed" when ``user`` is missing. The
        # property we care about is "doesn't validate", not the exact
        # reason string.
        with pytest.raises(TokenError):
            verify(op_token, SECRET_A, expected_site="t.example.com")
