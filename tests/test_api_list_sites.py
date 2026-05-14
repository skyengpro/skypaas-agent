"""Tests for the skypaas_agent.api.list_sites endpoint (PR #1A).

The endpoint imports ``frappe`` lazily and calls
``bench_ops.list_sites``. Tests stub both: ``frappe`` via a
``types.ModuleType`` shape matching what the endpoint touches, and
``bench_ops.list_sites`` via ``monkeypatch.setattr``.
"""

from __future__ import annotations

import sys
import time
import types
from unittest.mock import MagicMock

import pytest
from skypaas_agent.bench_ops import BenchOpResult
from skypaas_agent.tokens import OperationPayload, sign

SECRET = bytes.fromhex("a" * 64)
SITE = "tenant.example.com"


@pytest.fixture
def fake_frappe(monkeypatch: pytest.MonkeyPatch):
    """Minimal ``frappe`` module shape the list_sites endpoint touches."""
    frappe = types.ModuleType("frappe")
    frappe.local = types.SimpleNamespace(
        site=SITE,
        conf={"skypaas_agent_hmac_secret": SECRET.hex()},
        login_manager=MagicMock(),  # unused by list_sites; here for shared fixture compat
        response={},
    )
    frappe.log_error = MagicMock()
    monkeypatch.setitem(sys.modules, "frappe", frappe)
    return frappe


def _good_token(op: str = "list_sites", site: str = SITE, ttl: int = 60) -> str:
    return sign(
        OperationPayload(op=op, site=site, exp=int(time.time()) + ttl),
        SECRET,
    )


def _stub_bench_ops_list_sites(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sites: list[str] | None = None,
    ok: bool = True,
    stderr: str = "",
    duration_ms: int = 12,
):
    """Replace bench_ops.list_sites with a stub returning canned data."""
    from skypaas_agent import api as api_module

    def stub(*, runner=None):
        return (
            BenchOpResult(
                ok=ok,
                cmd=("bench", "list-sites"),
                stdout="\n".join(sites or []),
                stderr=stderr,
                exit_code=0 if ok else 1,
                duration_ms=duration_ms,
            ),
            sites or [],
        )

    monkeypatch.setattr(api_module.bench_ops, "list_sites", stub)


class TestSuccess:
    def test_happy_path_returns_sites(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(
            monkeypatch,
            sites=["acme-prod.homelab.local", "acme-staging.homelab.local"],
        )
        from skypaas_agent.api import list_sites

        result = list_sites(token=_good_token())
        assert result["ok"] is True
        assert result["sites"] == [
            "acme-prod.homelab.local",
            "acme-staging.homelab.local",
        ]
        assert result["duration_ms"] == 12
        # No HTTP error status was set
        assert "http_status_code" not in fake_frappe.local.response

    def test_empty_bench_returns_empty_list(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(monkeypatch, sites=[])
        from skypaas_agent.api import list_sites

        result = list_sites(token=_good_token())
        assert result["ok"] is True
        assert result["sites"] == []


class TestAuth:
    def test_missing_token_returns_401(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(monkeypatch, sites=["x.com"])
        from skypaas_agent.api import list_sites

        result = list_sites(token="")
        assert result["error"] == "invalid_token"
        assert fake_frappe.local.response["http_status_code"] == 401
        # bench_ops MUST NOT have been called when auth fails — defends
        # against any future refactor that moves the auth check below
        # the work.
        # (We assert by checking the result shape; if list_sites had
        # run, ``sites`` key would be present.)
        assert "sites" not in result

    def test_wrong_op_returns_401(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A token minted for op=create_site must not unlock list_sites."""
        _stub_bench_ops_list_sites(monkeypatch, sites=["x.com"])
        from skypaas_agent.api import list_sites

        wrong_op_token = _good_token(op="create_site")
        result = list_sites(token=wrong_op_token)
        assert result["error"] == "invalid_token"
        assert result["reason"] == "wrong_op"
        assert fake_frappe.local.response["http_status_code"] == 401

    def test_wrong_site_returns_401(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(monkeypatch, sites=["x.com"])
        from skypaas_agent.api import list_sites

        cross_site_token = _good_token(site="other-tenant.example.com")
        result = list_sites(token=cross_site_token)
        assert result["reason"] == "wrong_site"
        assert fake_frappe.local.response["http_status_code"] == 401

    def test_login_payload_token_rejected(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An operator's Login-as-Admin token must not unlock list_sites.
        The LoginPayload has a ``user`` field instead of ``op``;
        verify_operation rejects with reason=wrong_shape."""
        _stub_bench_ops_list_sites(monkeypatch, sites=["x.com"])
        from skypaas_agent.api import list_sites
        from skypaas_agent.tokens import LoginPayload

        login_token = sign(
            LoginPayload(user="Administrator", site=SITE, exp=int(time.time()) + 30), SECRET
        )
        result = list_sites(token=login_token)
        assert result["error"] == "invalid_token"
        assert result["reason"] == "wrong_shape"

    def test_expired_token_returns_401(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(monkeypatch, sites=["x.com"])
        from skypaas_agent.api import list_sites

        result = list_sites(token=_good_token(ttl=-10))
        assert result["reason"] == "expired"


class TestMisconfigured:
    def test_missing_secret_returns_500(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(monkeypatch, sites=["x.com"])
        fake_frappe.local.conf = {}  # secret missing
        from skypaas_agent.api import list_sites

        result = list_sites(token=_good_token())
        assert result["error"] == "agent_misconfigured"
        assert fake_frappe.local.response["http_status_code"] == 500

    def test_non_hex_secret_returns_500(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(monkeypatch, sites=["x.com"])
        fake_frappe.local.conf["skypaas_agent_hmac_secret"] = "not-hex!"
        from skypaas_agent.api import list_sites

        result = list_sites(token=_good_token())
        assert result["error"] == "agent_misconfigured"


class TestBenchFailure:
    def test_bench_cli_failure_returns_502(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(
            monkeypatch, sites=[], ok=False, stderr="bench: command not found"
        )
        from skypaas_agent.api import list_sites

        result = list_sites(token=_good_token())
        assert result["error"] == "bench_failed"
        assert "command not found" in result["stderr"]
        assert fake_frappe.local.response["http_status_code"] == 502

    def test_stderr_truncated_to_500_chars(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A bench that exploded with a multi-MB stack trace must not be
        echoed back to the control plane verbatim. Cap stderr at 500
        chars so logs stay sane."""
        long_stderr = "x" * 2000
        _stub_bench_ops_list_sites(monkeypatch, sites=[], ok=False, stderr=long_stderr)
        from skypaas_agent.api import list_sites

        result = list_sites(token=_good_token())
        assert len(result["stderr"]) <= 500


class TestAuditEvents:
    def test_success_emits_audit(self, fake_frappe, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_bench_ops_list_sites(monkeypatch, sites=["a.com", "b.com"])
        from skypaas_agent.api import list_sites

        list_sites(token=_good_token())
        titles = [
            c.kwargs.get("title", "") for c in fake_frappe.log_error.call_args_list
        ]
        assert any("list_sites.ok" in t for t in titles)

    def test_rejection_emits_audit_with_reason(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(monkeypatch, sites=["x.com"])
        from skypaas_agent.api import list_sites

        list_sites(token=_good_token(ttl=-10))
        rejections = [
            c
            for c in fake_frappe.log_error.call_args_list
            if "list_sites.rejected" in c.kwargs.get("title", "")
        ]
        assert rejections, "expected list_sites.rejected audit entry"
        assert "expired" in rejections[0].kwargs["message"]

    def test_bench_failure_emits_audit(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_ops_list_sites(monkeypatch, sites=[], ok=False, stderr="exploded")
        from skypaas_agent.api import list_sites

        list_sites(token=_good_token())
        failures = [
            c
            for c in fake_frappe.log_error.call_args_list
            if "list_sites.bench_failed" in c.kwargs.get("title", "")
        ]
        assert failures, "expected list_sites.bench_failed audit entry"


class TestDefaultRunnerExists:
    """Sanity that the production runner is wired up — not exercised in
    unit tests (it would call real subprocess), but the symbol must
    exist and be a CompletedProcess-returning callable."""

    def test_default_runner_is_subprocess_run(self) -> None:
        from skypaas_agent.bench_ops import _default_runner

        assert callable(_default_runner)
        # Don't actually invoke it — that would shell out. Confirm
        # the shape by reading source.
        import inspect

        src = inspect.getsource(_default_runner)
        assert "subprocess.run" in src
        assert "timeout=300" in src
        assert "check=False" in src
        assert "capture_output=True" in src
