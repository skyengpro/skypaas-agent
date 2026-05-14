"""In-memory job state for async agent operations.

ADR-0017 §10.1 (RESOLVED, R1.1): Phase 2 PR #2 ships the control-plane
with an in-memory queue + checkpointed ``agent_job_id`` in state.json;
full Valkey-backed RQ migration waits for multi-replica control plane
in v3. The agent side of that contract is in this module.

Lifecycle:

  CREATED ──(worker picks up)──▶ RUNNING ──(success)──▶ SUCCEEDED
     │                              │
     │                              └─(failure / exception)──▶ FAILED
     └─────(never picked up — shouldn't happen at v1 single-thread but
            still bound by TTL: kept 24h then evicted)

State is process-local — a pod restart loses in-flight jobs. The
control plane's reconcile loop polls ``GET /v1/jobs/{job_id}`` and
handles "404 not found" as "lost, presume failed; re-issue or alert".
The control plane's own state.json checkpoint of the ``agent_job_id``
is the durable record (per ADR-0017 §10.1).

Thread-safety: the registry uses a stdlib ``Lock`` because Frappe
serves requests from a gunicorn pool with multiple worker threads.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

JOB_TTL_SECONDS = 24 * 3600  # how long a terminal job stays queryable
EVICTION_INTERVAL_SECONDS = 600  # how often the registry sweeps stale entries


class JobState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


TERMINAL_STATES = frozenset({JobState.SUCCEEDED, JobState.FAILED})


@dataclass
class JobRecord:
    job_id: str
    op: str
    site: str
    state: JobState
    created_at: float
    started_at: float | None = None
    finished_at: float | None = None
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None  # populated when state=FAILED

    def to_dict(self) -> dict[str, Any]:
        """Serializable shape returned to control-plane pollers."""
        return {
            "job_id": self.job_id,
            "op": self.op,
            "site": self.site,
            "state": self.state.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result": self.result if self.state == JobState.SUCCEEDED else {},
            "error": self.error if self.state == JobState.FAILED else None,
        }


def _now() -> float:
    return time.time()


def new_job_id() -> str:
    """Generate a fresh job ID.

    UUIDv4 — no need for monotonic or sortable IDs at this scale;
    the registry is keyed by ID and the control plane's reconcile
    loop tracks ``created_at`` for ordering.
    """
    return str(uuid.uuid4())


class JobRegistry:
    """Process-local job state.

    The registry is held as a module-level singleton in production
    (one per Frappe pod). Tests instantiate their own; nothing in
    the API contract depends on the singleton being shared.

    Methods are thread-safe — the gunicorn pool may have multiple
    workers concurrently touching the same JobRegistry instance.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, JobRecord] = {}
        self._lock = threading.Lock()
        self._last_eviction = _now()

    def create(self, *, op: str, site: str) -> JobRecord:
        """Register a fresh job in PENDING state and return it."""
        record = JobRecord(
            job_id=new_job_id(),
            op=op,
            site=site,
            state=JobState.PENDING,
            created_at=_now(),
        )
        with self._lock:
            self._jobs[record.job_id] = record
            self._maybe_evict_locked()
        return record

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.get(job_id)

    def start(self, job_id: str) -> None:
        """Transition PENDING → RUNNING."""
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return
            if record.state == JobState.PENDING:
                record.state = JobState.RUNNING
                record.started_at = _now()

    def succeed(self, job_id: str, *, result: dict[str, Any]) -> None:
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None or record.state in TERMINAL_STATES:
                return
            record.state = JobState.SUCCEEDED
            record.finished_at = _now()
            record.result = result

    def fail(self, job_id: str, *, error: str) -> None:
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None or record.state in TERMINAL_STATES:
                return
            record.state = JobState.FAILED
            record.finished_at = _now()
            record.error = error

    def all_jobs(self) -> list[JobRecord]:
        """Snapshot of every known job. Useful for debugging /
        admin endpoints — not part of the control-plane API."""
        with self._lock:
            return list(self._jobs.values())

    def _maybe_evict_locked(self) -> None:
        """Periodically drop terminal jobs older than JOB_TTL_SECONDS.

        Called with the lock held; mutates the dict in place. Cheap
        even when called every create() because we gate on
        ``_last_eviction`` to avoid scanning every call.
        """
        now = _now()
        if now - self._last_eviction < EVICTION_INTERVAL_SECONDS:
            return
        cutoff = now - JOB_TTL_SECONDS
        to_drop = [
            job_id
            for job_id, record in self._jobs.items()
            if record.state in TERMINAL_STATES
            and record.finished_at is not None
            and record.finished_at < cutoff
        ]
        for job_id in to_drop:
            del self._jobs[job_id]
        self._last_eviction = now


# Module-level singleton — one per Frappe pod.
_REGISTRY: JobRegistry | None = None


def get_registry() -> JobRegistry:
    """Lazy-init the process-wide registry."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = JobRegistry()
    return _REGISTRY


def reset_registry_for_tests() -> None:
    """Test-only helper. Drops the singleton so each test sees a
    fresh registry."""
    global _REGISTRY
    _REGISTRY = None
