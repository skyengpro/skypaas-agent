"""Tests for the skypaas_agent.api.login_via_token endpoint.

The endpoint imports `frappe` lazily and reads site config + login
manager from frappe.local. We stub a minimal frappe module so we can
test the endpoint without a real Frappe runtime."""

from __future__ import annotations

import sys
import time
import types
from unittest.mock import MagicMock

import pytest
from skypaas_agent.tokens import LoginPayload, sign

SECRET = bytes.fromhex("a" * 64)
SITE = "tenant.example.com"


@pytest.fixture
def fake_frappe(monkeypatch: pytest.MonkeyPatch):
    """Build a minimal `frappe` module shape the endpoint touches."""
    frappe = types.ModuleType("frappe")
    frappe.local = types.SimpleNamespace(
        site=SITE,
        conf={"skypaas_agent_hmac_secret": SECRET.hex()},
        login_manager=MagicMock(),
        response={},
    )
    frappe.log_error = MagicMock()
    monkeypatch.setitem(sys.modules, "frappe", frappe)
    return frappe


def _token(user: str = "Administrator", site: str = SITE, ttl: int = 60) -> str:
    return sign(LoginPayload(user=user, site=site, exp=int(time.time()) + ttl), SECRET)


class TestSuccess:
    def test_valid_token_calls_login_as(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        result = login_via_token(token=_token())
        # The endpoint returns None on success; the response carries the redirect.
        assert result is None
        fake_frappe.local.login_manager.login_as.assert_called_once_with("Administrator")
        assert fake_frappe.local.response["type"] == "redirect"
        assert fake_frappe.local.response["location"] == "/app"

    def test_next_param_honored_when_safe(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        login_via_token(token=_token(), next="/app/sales-invoice")
        assert fake_frappe.local.response["location"] == "/app/sales-invoice"

    def test_open_redirect_rejected(self, fake_frappe) -> None:
        """A token-holder shouldn't be able to bounce the operator to
        evil.example.com after login. Anything that doesn't start with
        '/' falls back to /app."""
        from skypaas_agent.api import login_via_token

        login_via_token(token=_token(), next="https://evil.example.com/")
        assert fake_frappe.local.response["location"] == "/app"


class TestRejection:
    def test_missing_secret_returns_500(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        fake_frappe.local.conf = {}  # secret missing
        result = login_via_token(token=_token())
        assert result["error"] == "agent_misconfigured"
        assert fake_frappe.local.response["http_status_code"] == 500
        fake_frappe.local.login_manager.login_as.assert_not_called()

    def test_non_hex_secret_returns_500(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        fake_frappe.local.conf["skypaas_agent_hmac_secret"] = "not-hex-at-all-xyz!"
        result = login_via_token(token=_token())
        assert result["error"] == "agent_misconfigured"
        fake_frappe.local.login_manager.login_as.assert_not_called()

    def test_bad_signature_returns_401(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        # Sign with a different secret
        bad = sign(
            LoginPayload(user="Administrator", site=SITE, exp=int(time.time()) + 60),
            bytes.fromhex("b" * 64),
        )
        result = login_via_token(token=bad)
        assert result["error"] == "invalid_token"
        assert result["reason"] == "bad_signature"
        assert fake_frappe.local.response["http_status_code"] == 401
        fake_frappe.local.login_manager.login_as.assert_not_called()

    def test_expired_token_returns_401(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        result = login_via_token(token=_token(ttl=-10))
        assert result["error"] == "invalid_token"
        assert result["reason"] == "expired"
        fake_frappe.local.login_manager.login_as.assert_not_called()

    def test_token_for_other_site_returns_401(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        result = login_via_token(token=_token(site="other.example.com"))
        assert result["reason"] == "wrong_site"
        fake_frappe.local.login_manager.login_as.assert_not_called()

    def test_malformed_token_returns_401(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        result = login_via_token(token="not.a.token.at.all")
        assert result["reason"] == "malformed"
        fake_frappe.local.login_manager.login_as.assert_not_called()


class TestAuditEvents:
    def test_success_emits_audit(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        login_via_token(token=_token())
        fake_frappe.log_error.assert_called()
        kwargs = fake_frappe.log_error.call_args.kwargs
        assert "login_succeeded" in kwargs["title"]

    def test_rejection_emits_audit_with_reason(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        login_via_token(token=_token(ttl=-10))
        # Find the log entry for the rejection
        calls = [
            c
            for c in fake_frappe.log_error.call_args_list
            if "login_rejected" in c.kwargs.get("title", "")
        ]
        assert calls, "expected login_rejected audit entry"
        # The fields dict should carry the rejection reason
        assert "expired" in calls[0].kwargs["message"]
