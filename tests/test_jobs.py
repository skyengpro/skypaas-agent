"""Tests for the in-memory job registry."""

from __future__ import annotations

import threading
import time

import pytest
from skypaas_agent.jobs import (
    EVICTION_INTERVAL_SECONDS,
    JOB_TTL_SECONDS,
    JobRegistry,
    JobState,
    get_registry,
    new_job_id,
    reset_registry_for_tests,
)


@pytest.fixture(autouse=True)
def _isolated_registry():
    """Each test gets a fresh module-level registry."""
    reset_registry_for_tests()
    yield
    reset_registry_for_tests()


class TestNewJobId:
    def test_returns_uuid_string(self) -> None:
        job_id = new_job_id()
        assert isinstance(job_id, str)
        assert len(job_id) == 36  # UUIDv4 string form
        assert job_id.count("-") == 4

    def test_two_ids_are_distinct(self) -> None:
        ids = {new_job_id() for _ in range(100)}
        assert len(ids) == 100


class TestCreate:
    def test_record_starts_pending(self) -> None:
        reg = JobRegistry()
        record = reg.create(op="create_site", site="t.example.com")
        assert record.state == JobState.PENDING
        assert record.op == "create_site"
        assert record.site == "t.example.com"
        assert record.started_at is None
        assert record.finished_at is None

    def test_record_carries_a_unique_id(self) -> None:
        reg = JobRegistry()
        a = reg.create(op="create_site", site="t.example.com")
        b = reg.create(op="create_site", site="t.example.com")
        assert a.job_id != b.job_id

    def test_created_at_is_now(self) -> None:
        reg = JobRegistry()
        before = time.time()
        record = reg.create(op="x", site="t")
        after = time.time()
        assert before - 1 <= record.created_at <= after + 1


class TestStateTransitions:
    def test_pending_to_running(self) -> None:
        reg = JobRegistry()
        record = reg.create(op="create_site", site="t")
        reg.start(record.job_id)
        fetched = reg.get(record.job_id)
        assert fetched is not None
        assert fetched.state == JobState.RUNNING
        assert fetched.started_at is not None

    def test_running_to_succeeded(self) -> None:
        reg = JobRegistry()
        record = reg.create(op="x", site="t")
        reg.start(record.job_id)
        reg.succeed(record.job_id, result={"sites": ["a"]})
        fetched = reg.get(record.job_id)
        assert fetched is not None
        assert fetched.state == JobState.SUCCEEDED
        assert fetched.result == {"sites": ["a"]}
        assert fetched.finished_at is not None
        assert fetched.error is None

    def test_running_to_failed(self) -> None:
        reg = JobRegistry()
        record = reg.create(op="x", site="t")
        reg.start(record.job_id)
        reg.fail(record.job_id, error="bench: exploded")
        fetched = reg.get(record.job_id)
        assert fetched is not None
        assert fetched.state == JobState.FAILED
        assert fetched.error == "bench: exploded"
        assert fetched.result == {}  # explicit no result on failure

    def test_terminal_state_is_sticky(self) -> None:
        """Once a job is succeeded/failed, further transitions are
        no-ops — the worker should never overwrite a recorded outcome.
        Defends against double-completion bugs."""
        reg = JobRegistry()
        record = reg.create(op="x", site="t")
        reg.succeed(record.job_id, result={"a": 1})
        reg.fail(record.job_id, error="too late")  # ignored
        fetched = reg.get(record.job_id)
        assert fetched is not None
        assert fetched.state == JobState.SUCCEEDED
        assert fetched.result == {"a": 1}

    def test_start_on_unknown_id_is_noop(self) -> None:
        reg = JobRegistry()
        reg.start("no-such-id")  # MUST NOT raise

    def test_succeed_on_unknown_id_is_noop(self) -> None:
        reg = JobRegistry()
        reg.succeed("no-such-id", result={})  # MUST NOT raise


class TestGet:
    def test_returns_none_for_unknown(self) -> None:
        reg = JobRegistry()
        assert reg.get("no-such-id") is None

    def test_returns_record_for_known(self) -> None:
        reg = JobRegistry()
        created = reg.create(op="x", site="t")
        fetched = reg.get(created.job_id)
        assert fetched is created  # same object


class TestSerialize:
    def test_to_dict_omits_result_on_failure(self) -> None:
        reg = JobRegistry()
        record = reg.create(op="x", site="t")
        reg.fail(record.job_id, error="boom")
        d = reg.get(record.job_id).to_dict()  # type: ignore[union-attr]
        assert d["state"] == "failed"
        assert d["result"] == {}
        assert d["error"] == "boom"

    def test_to_dict_omits_error_on_success(self) -> None:
        reg = JobRegistry()
        record = reg.create(op="x", site="t")
        reg.succeed(record.job_id, result={"k": "v"})
        d = reg.get(record.job_id).to_dict()  # type: ignore[union-attr]
        assert d["state"] == "succeeded"
        assert d["result"] == {"k": "v"}
        assert d["error"] is None


class TestThreadSafety:
    def test_concurrent_create_no_id_collision(self) -> None:
        reg = JobRegistry()
        ids: list[str] = []

        def worker() -> None:
            for _ in range(50):
                r = reg.create(op="x", site="t")
                ids.append(r.job_id)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(ids) == 200
        assert len(set(ids)) == 200, "duplicate job IDs under concurrent create"


class TestEviction:
    def test_terminal_jobs_drop_after_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """We can't wait JOB_TTL_SECONDS in a unit test; monkeypatch
        the registry's internal _now to simulate elapsed time."""
        import skypaas_agent.jobs as jobs_module

        # Anchor the clock
        fake_now = [1_000_000.0]
        monkeypatch.setattr(jobs_module, "_now", lambda: fake_now[0])

        reg = JobRegistry()
        record = reg.create(op="x", site="t")
        reg.succeed(record.job_id, result={})

        # Advance past TTL + eviction interval
        fake_now[0] += JOB_TTL_SECONDS + EVICTION_INTERVAL_SECONDS + 1

        # Trigger eviction via a new create
        reg.create(op="x", site="t")

        assert reg.get(record.job_id) is None, "old terminal job should be evicted"

    def test_nonterminal_jobs_are_not_evicted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A long-running job (still PENDING/RUNNING after the TTL —
        not realistic in production but defensive) must not be
        evicted."""
        import skypaas_agent.jobs as jobs_module

        fake_now = [1_000_000.0]
        monkeypatch.setattr(jobs_module, "_now", lambda: fake_now[0])

        reg = JobRegistry()
        record = reg.create(op="x", site="t")
        reg.start(record.job_id)  # RUNNING, no finished_at

        fake_now[0] += JOB_TTL_SECONDS + EVICTION_INTERVAL_SECONDS + 1
        reg.create(op="x", site="t")  # trigger eviction

        assert reg.get(record.job_id) is not None, "RUNNING job must not be evicted"


class TestModuleSingleton:
    def test_get_registry_returns_same_instance(self) -> None:
        a = get_registry()
        b = get_registry()
        assert a is b

    def test_reset_creates_a_fresh_registry(self) -> None:
        a = get_registry()
        record = a.create(op="x", site="t")
        reset_registry_for_tests()
        b = get_registry()
        assert a is not b
        assert b.get(record.job_id) is None
