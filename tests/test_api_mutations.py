"""Tests for the Phase 2 mutation endpoints + get_job.

These tests exercise the full async wire: ``create_site`` returns
``{job_id, state: "pending"}``, the worker runs (synchronously via
the stubbed ``frappe.enqueue``), and ``get_job`` returns the
terminal state.

What we stub:

  - ``frappe`` module — same shape as the login_via_token fixture.
  - ``frappe.enqueue`` — invoked sync so the worker runs immediately
    inside the test thread. The dotted method name is resolved by
    looking it up on the ``skypaas_agent.api`` module.
  - ``locks.get_valkey_client`` — returns a fake client whose
    ``lock(...)`` returns a context manager that's always available.
    Tests that need lock-busy / lock-unavailable failures override
    the fake.
  - ``bench_ops.<op>`` — stubbed per test to return canned outcomes
    (success, failure, etc.).
"""

from __future__ import annotations

import sys
import time
import types
from unittest.mock import MagicMock

import pytest
from skypaas_agent.bench_ops import BenchOpResult
from skypaas_agent.jobs import JobState, reset_registry_for_tests
from skypaas_agent.tokens import OperationPayload, sign

SECRET = bytes.fromhex("a" * 64)
SITE = "tenant.example.com"


class _FakeLockCtx:
    def __init__(self, *, busy: bool = False) -> None:
        self.busy = busy

    def __enter__(self):
        return not self.busy

    def __exit__(self, *args):
        return None


class _FakeValkey:
    def __init__(self, *, busy: bool = False) -> None:
        self.busy = busy
        self.calls: list[tuple[str, float, float]] = []

    def lock(self, name: str, timeout: float, blocking_timeout: float):
        self.calls.append((name, timeout, blocking_timeout))
        return _FakeLockCtx(busy=self.busy)


@pytest.fixture(autouse=True)
def _isolated_registry():
    reset_registry_for_tests()
    yield
    reset_registry_for_tests()


@pytest.fixture
def fake_frappe(monkeypatch: pytest.MonkeyPatch):
    """Frappe stub. ``frappe.enqueue`` is configured to invoke the
    target method synchronously inside the same thread — production
    routes through RQ workers, but tests want deterministic execution."""
    frappe = types.ModuleType("frappe")
    frappe.local = types.SimpleNamespace(
        site=SITE,
        conf={"skypaas_agent_hmac_secret": SECRET.hex()},
        login_manager=MagicMock(),
        response={},
    )
    frappe.log_error = MagicMock()

    def sync_enqueue(method_name: str, **kwargs):
        """Resolve the dotted path against skypaas_agent.api and call
        sync. Strips the queue= and other RQ-specific kwargs."""
        kwargs.pop("queue", None)
        kwargs.pop("timeout", None)
        kwargs.pop("now", None)
        if method_name.startswith("skypaas_agent.api."):
            from skypaas_agent import api as api_module

            fn_name = method_name.split(".")[-1]
            getattr(api_module, fn_name)(**kwargs)
        else:
            raise AssertionError(f"unexpected enqueue target: {method_name}")

    frappe.enqueue = sync_enqueue
    monkeypatch.setitem(sys.modules, "frappe", frappe)
    return frappe


@pytest.fixture
def fake_valkey(monkeypatch: pytest.MonkeyPatch):
    """Default Valkey stub — lock always acquired immediately."""
    client = _FakeValkey()
    from skypaas_agent import locks

    monkeypatch.setattr(locks, "get_valkey_client", lambda: client)
    return client


def _good_token(op: str, site: str = SITE, ttl: int = 60) -> str:
    return sign(OperationPayload(op=op, site=site, exp=int(time.time()) + ttl), SECRET)


def _stub_bench_op(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    *,
    ok: bool = True,
    stderr: str = "",
    duration_ms: int = 42,
):
    """Replace a bench_ops.<name> function with a canned-result stub."""
    from skypaas_agent import bench_ops

    def stub(*args, **kwargs):
        return BenchOpResult(
            ok=ok,
            cmd=("bench", name, *args),
            stdout="",
            stderr=stderr,
            exit_code=0 if ok else 1,
            duration_ms=duration_ms,
        )

    monkeypatch.setattr(bench_ops, name, stub)


# ============================================================
#                         create_site
# ============================================================


class TestCreateSiteSuccess:
    def test_happy_path(self, fake_frappe, fake_valkey, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_bench_op(monkeypatch, "create_site")
        from skypaas_agent.api import create_site, get_job

        result = create_site(
            token=_good_token("create_site"),
            site_name="acme.homelab.local",
            admin_email="ops@example.com",
            admin_password="LongEnoughPw1!",
        )
        assert "job_id" in result
        assert result["state"] == "pending"
        assert fake_frappe.local.response["http_status_code"] == 202

        # Worker has run sync via enqueue stub — poll job
        job = get_job(token=_good_token("get_job"), job_id=result["job_id"])
        assert job["state"] == JobState.SUCCEEDED.value
        assert job["op"] == "create_site"
        assert job["site"] == SITE  # the AGENT-host site, not the new site

    def test_lock_was_acquired_before_op(
        self, fake_frappe, fake_valkey, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_op(monkeypatch, "create_site")
        from skypaas_agent.api import create_site

        create_site(
            token=_good_token("create_site"),
            site_name="x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw1!",
        )
        # Lock was acquired with the expected key
        assert len(fake_valkey.calls) == 1
        name, _ttl, _blocking_timeout = fake_valkey.calls[0]
        assert name == "skypaas:bench:write"


class TestCreateSiteValidation:
    def test_bad_site_name_returns_422(self, fake_frappe, fake_valkey) -> None:
        from skypaas_agent.api import create_site

        result = create_site(
            token=_good_token("create_site"),
            site_name="no-dot-here",
            admin_email="a@b.com",
            admin_password="LongEnoughPw1!",
        )
        assert result["error"] == "invalid_site_name"
        assert fake_frappe.local.response["http_status_code"] == 422

    def test_short_password_returns_422(self, fake_frappe, fake_valkey) -> None:
        from skypaas_agent.api import create_site

        result = create_site(
            token=_good_token("create_site"),
            site_name="x.com",
            admin_email="a@b.com",
            admin_password="short",
        )
        assert result["error"] == "invalid_admin_password"

    def test_bad_email_returns_422(self, fake_frappe, fake_valkey) -> None:
        from skypaas_agent.api import create_site

        result = create_site(
            token=_good_token("create_site"),
            site_name="x.com",
            admin_email="not-an-email",
            admin_password="LongEnoughPw1!",
        )
        assert result["error"] == "invalid_admin_email"


class TestCreateSiteAuth:
    def test_missing_token_returns_401(self, fake_frappe, fake_valkey) -> None:
        from skypaas_agent.api import create_site

        result = create_site(
            token="", site_name="x.com", admin_email="a@b.com", admin_password="LongEnoughPw1!"
        )
        assert result["error"] == "invalid_token"
        assert fake_frappe.local.response["http_status_code"] == 401

    def test_wrong_op_token_returns_401(self, fake_frappe, fake_valkey) -> None:
        """A token for op=list_sites must not unlock create_site."""
        from skypaas_agent.api import create_site

        result = create_site(
            token=_good_token("list_sites"),
            site_name="x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw1!",
        )
        assert result["reason"] == "wrong_op"


class TestCreateSiteFailureModes:
    def test_bench_failure_marks_job_failed(
        self, fake_frappe, fake_valkey, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_op(monkeypatch, "create_site", ok=False, stderr="db locked")
        from skypaas_agent.api import create_site, get_job

        result = create_site(
            token=_good_token("create_site"),
            site_name="x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw1!",
        )
        job = get_job(token=_good_token("get_job"), job_id=result["job_id"])
        assert job["state"] == JobState.FAILED.value
        assert "db locked" in job["error"]

    def test_lock_busy_marks_job_failed(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        busy_client = _FakeValkey(busy=True)
        from skypaas_agent import locks

        monkeypatch.setattr(locks, "get_valkey_client", lambda: busy_client)
        _stub_bench_op(monkeypatch, "create_site")
        from skypaas_agent.api import create_site, get_job

        result = create_site(
            token=_good_token("create_site"),
            site_name="x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw1!",
        )
        job = get_job(token=_good_token("get_job"), job_id=result["job_id"])
        assert job["state"] == JobState.FAILED.value
        assert "lock_busy" in job["error"]

    def test_valkey_unavailable_marks_job_failed(
        self, fake_frappe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from skypaas_agent import locks

        monkeypatch.setattr(locks, "get_valkey_client", lambda: None)
        _stub_bench_op(monkeypatch, "create_site")
        from skypaas_agent.api import create_site, get_job

        result = create_site(
            token=_good_token("create_site"),
            site_name="x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw1!",
        )
        job = get_job(token=_good_token("get_job"), job_id=result["job_id"])
        assert job["state"] == JobState.FAILED.value
        assert "valkey_unavailable" in job["error"]


# ============================================================
#                          drop_site
# ============================================================


class TestDropSite:
    def test_happy_path(self, fake_frappe, fake_valkey, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_bench_op(monkeypatch, "drop_site")
        from skypaas_agent.api import drop_site, get_job

        result = drop_site(token=_good_token("drop_site"), site_name="x.com")
        assert result["state"] == "pending"
        job = get_job(token=_good_token("get_job"), job_id=result["job_id"])
        assert job["state"] == JobState.SUCCEEDED.value

    def test_invalid_site_name_422(self, fake_frappe, fake_valkey) -> None:
        from skypaas_agent.api import drop_site

        result = drop_site(token=_good_token("drop_site"), site_name="")
        assert result["error"] == "invalid_site_name"
        assert fake_frappe.local.response["http_status_code"] == 422


# ============================================================
#                         backup_site
# ============================================================


class TestBackupSite:
    def test_happy_path(self, fake_frappe, fake_valkey, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_bench_op(monkeypatch, "backup_site")
        from skypaas_agent.api import backup_site, get_job

        result = backup_site(token=_good_token("backup_site"), site_name="x.com")
        job = get_job(token=_good_token("get_job"), job_id=result["job_id"])
        assert job["state"] == JobState.SUCCEEDED.value
        assert job["op"] == "backup_site"


# ============================================================
#                        restore_site
# ============================================================


class TestRestoreSite:
    def test_happy_path(self, fake_frappe, fake_valkey, monkeypatch: pytest.MonkeyPatch) -> None:
        _stub_bench_op(monkeypatch, "restore_site")
        from skypaas_agent.api import get_job, restore_site

        result = restore_site(
            token=_good_token("restore_site"),
            site_name="x.com",
            backup_path="/tmp/backup.sql.gz",
        )
        job = get_job(token=_good_token("get_job"), job_id=result["job_id"])
        assert job["state"] == JobState.SUCCEEDED.value

    def test_missing_backup_path_422(self, fake_frappe, fake_valkey) -> None:
        from skypaas_agent.api import restore_site

        result = restore_site(
            token=_good_token("restore_site"), site_name="x.com", backup_path=""
        )
        assert result["error"] == "missing_backup_path"


# ============================================================
#                          get_job
# ============================================================


class TestGetJob:
    def test_unknown_id_returns_404(self, fake_frappe) -> None:
        from skypaas_agent.api import get_job

        result = get_job(token=_good_token("get_job"), job_id="no-such-job")
        assert result["error"] == "job_not_found"
        assert fake_frappe.local.response["http_status_code"] == 404

    def test_missing_id_returns_422(self, fake_frappe) -> None:
        from skypaas_agent.api import get_job

        result = get_job(token=_good_token("get_job"), job_id="")
        assert result["error"] == "missing_job_id"
        assert fake_frappe.local.response["http_status_code"] == 422

    def test_wrong_op_token_rejected(self, fake_frappe) -> None:
        """A token for op=create_site cannot poll get_job — defense
        in depth, even though job-poll is read-only."""
        from skypaas_agent.api import get_job

        result = get_job(token=_good_token("create_site"), job_id="anything")
        assert result["reason"] == "wrong_op"


# ============================================================
#                     Cross-shape isolation
# ============================================================


class TestTokenShapeIsolation:
    """A token minted for ANY operation must NOT be usable on the
    Login-as-Admin endpoint, and a LoginPayload token must NOT
    unlock any operation endpoint. The verify_operation /
    verify wrong_shape rejection is already covered in
    test_tokens.py; here we confirm the API layer surfaces it."""

    def test_login_token_cannot_unlock_create_site(
        self, fake_frappe, fake_valkey
    ) -> None:
        from skypaas_agent.api import create_site
        from skypaas_agent.tokens import LoginPayload

        login_token = sign(
            LoginPayload(user="Administrator", site=SITE, exp=int(time.time()) + 30),
            SECRET,
        )
        result = create_site(
            token=login_token,
            site_name="x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw1!",
        )
        assert result["reason"] == "wrong_shape"

    def test_operation_token_cannot_unlock_login(self, fake_frappe) -> None:
        from skypaas_agent.api import login_via_token

        op_token = _good_token("login_via_token")  # ANY op, doesn't matter
        result = login_via_token(token=op_token)
        # `verify` (LoginPayload) rejects this — exact reason is
        # implementation-dependent (malformed or KeyError-as-malformed
        # in current code) — we only assert it failed to authenticate.
        assert isinstance(result, dict)
        assert result.get("error") == "invalid_token"


# ============================================================
#                         Audit events
# ============================================================


class TestAuditEvents:
    def test_queued_and_ok_events(
        self, fake_frappe, fake_valkey, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_bench_op(monkeypatch, "create_site")
        from skypaas_agent.api import create_site

        create_site(
            token=_good_token("create_site"),
            site_name="x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw1!",
        )
        titles = [
            c.kwargs.get("title", "") for c in fake_frappe.log_error.call_args_list
        ]
        assert any("create_site.queued" in t for t in titles)
        assert any("create_site.ok" in t for t in titles)

    def test_rejection_emits_rejected_event(self, fake_frappe, fake_valkey) -> None:
        from skypaas_agent.api import create_site

        create_site(
            token=_good_token("list_sites"),  # wrong op
            site_name="x.com",
            admin_email="a@b.com",
            admin_password="LongEnoughPw1!",
        )
        titles = [
            c.kwargs.get("title", "") for c in fake_frappe.log_error.call_args_list
        ]
        assert any("create_site.rejected" in t for t in titles)
