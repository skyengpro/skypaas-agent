"""Per-bench lock primitive for serializing mutating site operations.

ADR-0017 §3.1: ``bench new-site`` (and ``drop-site``, ``restore``) are
not safe to run concurrently against the same bench because they
mutate ``currentsite.txt`` and the shared ``sites/`` directory. The
agent serialises mutating operations via a lock held against the
chart's bundled **Valkey** (BSD-3-Clause). See ADR-0017 §11 for the
license rationale — never Redis-the-product (RSAL+SSPL).

We deliberately decouple the agent code from a specific Valkey
client: ``acquire_bench_lock`` takes any object that implements the
``RedisLikeClient`` Protocol (just ``lock(name, timeout, blocking_timeout)``).
Production: ``redis.Redis`` from ``redis-py`` pointed at the
chart's Valkey service. Tests: an in-memory fake that records
acquire/release for assertions.

Wire protocol: RESP — same on Valkey-the-server and `redis-py` (MIT)
client side. We never ship Redis-the-product, only its client lib.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Protocol, runtime_checkable

# The lock key is fixed per-bench because there's exactly one bench
# per pod. A namespaced key avoids colliding with Frappe's own
# RQ-internal locks.
BENCH_LOCK_KEY = "skypaas:bench:write"

# Lock-holder TTL: hard ceiling on how long ANY single operation can
# hold the lock. ``bench new-site`` and ``bench restore`` both legit
# can hit several minutes. We cap at 10 minutes — if an op exceeds
# this, the lock is force-released by Valkey to prevent a wedged
# worker from blocking the bench forever.
LOCK_TTL_SECONDS = 600

# How long ``acquire_bench_lock`` blocks waiting for a busy lock
# before returning a ``LockBusyError``. Callers handling the busy
# case can retry; for HTTP endpoints we surface 409 immediately.
DEFAULT_BLOCKING_TIMEOUT_SECONDS = 5


@runtime_checkable
class RedisLikeClient(Protocol):
    """Minimal Valkey/redis-py shape the lock primitive needs.

    ``lock(name, timeout, blocking_timeout)`` returns a context-manager-shaped
    object. ``__enter__`` returns truthy on success, raises on failure
    to acquire. ``__exit__`` releases.
    """

    def lock(self, name: str, timeout: float, blocking_timeout: float):  # type: ignore[no-untyped-def]
        ...


class LockBusyError(RuntimeError):
    """Raised when ``acquire_bench_lock`` times out waiting for the
    lock to be available. Maps to HTTP 409 at the API layer."""


class LockUnavailableError(RuntimeError):
    """Raised when the Valkey client itself can't be reached. Maps
    to HTTP 503 — the agent's transient failure, not the caller's
    fault."""


@contextmanager
def acquire_bench_lock(
    client: RedisLikeClient,
    *,
    blocking_timeout: float = DEFAULT_BLOCKING_TIMEOUT_SECONDS,
    ttl_seconds: float = LOCK_TTL_SECONDS,
) -> Iterator[None]:
    """Hold the per-bench write lock for the duration of the ``with`` block.

    Raises ``LockBusyError`` if the lock is held by another worker
    and doesn't free within ``blocking_timeout``. Raises
    ``LockUnavailableError`` if the Valkey backend itself is
    unreachable.

    Example::

        with acquire_bench_lock(get_valkey_client()):
            run_bench_new_site(...)
    """
    try:
        lock = client.lock(BENCH_LOCK_KEY, timeout=ttl_seconds, blocking_timeout=blocking_timeout)
    except Exception as e:
        raise LockUnavailableError(f"valkey client.lock() failed: {e}") from e

    acquired = False
    try:
        try:
            acquired = lock.__enter__()
        except Exception as e:
            # redis-py raises ``LockError`` on timeout. We don't import
            # the class (would pin a redis-py version); we treat any
            # acquire-time exception as "busy". The Valkey-down case
            # was raised above by the ``client.lock(...)`` call itself.
            raise LockBusyError(
                f"bench lock held by another worker after {blocking_timeout}s"
            ) from e
        if not acquired:
            # Some redis-py versions return False from blocking_timeout
            # rather than raising. Treat as busy.
            raise LockBusyError(
                f"bench lock held by another worker after {blocking_timeout}s"
            )
        yield
    finally:
        if acquired:
            try:
                lock.__exit__(None, None, None)
            except Exception:
                # Best-effort release — if Valkey hiccups during
                # release, the TTL will eventually clear it. Don't
                # crash a successful operation on release-time noise.
                pass


def get_valkey_client():  # noqa: ANN201 — runtime-decided shape
    """Build the production Valkey client.

    Reads ``redis_cache.host`` / ``redis_cache.port`` from
    ``frappe.local.conf`` — Frappe's existing config keys for the
    bundled Valkey cache service. Frappe already depends on
    ``redis-py`` (its RQ backend), so we don't add a new runtime
    dep. The class name is ``redis.Redis`` but the server it talks
    to is Valkey — see module docstring + ADR-0017 §11 for the
    license rationale.

    Returns ``None`` if Frappe config doesn't declare a cache host
    (e.g. running outside a real bench in dev). Callers must handle
    None by surfacing 503.
    """
    try:
        import frappe  # noqa: PLC0415
        import redis  # noqa: PLC0415 — redis-py client, talks Valkey
    except ImportError:
        return None

    host = frappe.local.conf.get("redis_cache") or "redis://localhost:11311"
    # Frappe writes redis_cache as either a URL or a host:port dict.
    if isinstance(host, str):
        return redis.Redis.from_url(host)
    if isinstance(host, dict):
        return redis.Redis(host=host.get("host", "localhost"), port=host.get("port", 11311))
    return None
