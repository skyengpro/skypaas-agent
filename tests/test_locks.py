"""Tests for the per-bench Valkey lock primitive."""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from skypaas_agent.locks import (
    BENCH_LOCK_KEY,
    LOCK_TTL_SECONDS,
    LockBusyError,
    LockUnavailableError,
    acquire_bench_lock,
)


class _FakeLockCtx:
    """Mimics the context manager returned by ``redis.Redis.lock``."""

    def __init__(self, *, busy: bool = False, raise_on_enter: bool = False) -> None:
        self.busy = busy
        self.raise_on_enter = raise_on_enter
        self.entered = False
        self.released = False

    def __enter__(self):
        if self.raise_on_enter:
            raise RuntimeError("lock acquisition timed out")
        if self.busy:
            return False
        self.entered = True
        return True

    def __exit__(self, *args):
        self.released = True
        return None


class _FakeClient:
    """Records lock() calls + returns canned ctx managers."""

    def __init__(self, *, ctx_factory=None, lock_raises: bool = False) -> None:
        self.calls: list[tuple[str, float, float]] = []
        self._ctx_factory = ctx_factory or (lambda: _FakeLockCtx())
        self._lock_raises = lock_raises

    def lock(self, name: str, timeout: float, blocking_timeout: float):  # noqa: D401
        self.calls.append((name, timeout, blocking_timeout))
        if self._lock_raises:
            raise ConnectionError("valkey is down")
        return self._ctx_factory()


class TestAcquireSuccess:
    def test_happy_path_holds_and_releases(self) -> None:
        ctx = _FakeLockCtx()
        client = _FakeClient(ctx_factory=lambda: ctx)

        with acquire_bench_lock(client):
            pass

        assert ctx.entered is True
        assert ctx.released is True

    def test_lock_called_with_correct_key_and_ttl(self) -> None:
        client = _FakeClient()
        with acquire_bench_lock(client, ttl_seconds=42.0, blocking_timeout=3.0):
            pass
        assert client.calls == [(BENCH_LOCK_KEY, 42.0, 3.0)]

    def test_default_ttl_is_the_module_constant(self) -> None:
        client = _FakeClient()
        with acquire_bench_lock(client):
            pass
        assert client.calls[0][1] == LOCK_TTL_SECONDS


class TestAcquireBusy:
    def test_busy_returns_false_raises_lock_busy(self) -> None:
        """Some redis-py versions return False from blocking_timeout
        rather than raising. We treat that as busy."""
        client = _FakeClient(ctx_factory=lambda: _FakeLockCtx(busy=True))

        with pytest.raises(LockBusyError) as ei:
            with acquire_bench_lock(client, blocking_timeout=1.0):
                pytest.fail("body should not run when lock is busy")
        assert "another worker" in str(ei.value)

    def test_busy_raise_on_enter_maps_to_lock_busy(self) -> None:
        """Other redis-py versions raise LockError on timeout. We
        treat any acquire-time exception as busy."""
        client = _FakeClient(ctx_factory=lambda: _FakeLockCtx(raise_on_enter=True))

        with pytest.raises(LockBusyError):
            with acquire_bench_lock(client):
                pass


class TestUnavailable:
    def test_client_lock_raises_maps_to_unavailable(self) -> None:
        """If ``client.lock(...)`` itself raises (Valkey unreachable
        before we even attempt acquire), that's a different failure
        mode mapping to HTTP 503, not 409."""
        client = _FakeClient(lock_raises=True)

        with pytest.raises(LockUnavailableError) as ei:
            with acquire_bench_lock(client):
                pass
        assert "valkey" in str(ei.value).lower()


class TestRelease:
    def test_release_failure_is_swallowed(self) -> None:
        """If the lock release fails (e.g. Valkey hiccup), the body's
        success should not be undone. The TTL eventually clears it."""

        class _AngryReleaseCtx(_FakeLockCtx):
            def __exit__(self, *args):
                raise RuntimeError("valkey hiccup during release")

        ctx = _AngryReleaseCtx()
        client = _FakeClient(ctx_factory=lambda: ctx)

        # Should NOT raise — release failure is swallowed
        with acquire_bench_lock(client):
            pass
        assert ctx.entered is True


class TestExclusive:
    def test_serialised_within_one_process(self) -> None:
        """Two sequential acquires on the same client both succeed —
        the first releases before the second enters. (Real cross-
        process exclusion is Valkey's job; we trust redis-py's
        implementation, which we don't re-test here.)"""
        client = _FakeClient()
        with acquire_bench_lock(client):
            pass
        with acquire_bench_lock(client):
            pass
        # Two lock() calls observed
        assert len(client.calls) == 2


class TestProtocolShape:
    def test_redis_like_client_protocol_accepts_anything_with_lock(self) -> None:
        """Anything with a ``lock(name, timeout, blocking_timeout)``
        signature satisfies the Protocol — including a MagicMock,
        which is what most test fixtures wire up."""
        from skypaas_agent.locks import RedisLikeClient

        @contextmanager
        def trivial_ctx():
            yield

        class HasLock:
            def lock(self, name, timeout, blocking_timeout):
                return _FakeLockCtx()

        assert isinstance(HasLock(), RedisLikeClient)

        # A purely-empty class should NOT satisfy the protocol
        class NoLock:
            pass

        assert not isinstance(NoLock(), RedisLikeClient)
