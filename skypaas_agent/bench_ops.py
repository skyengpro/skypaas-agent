"""Thin wrappers around the ``bench`` CLI for Phase 2 site operations.

Each public function in this module:

  - Takes a ``runner`` callable for dependency injection (the default
    runs ``subprocess.run``; tests inject a stub returning canned
    output without needing a Frappe runtime).
  - Returns a typed ``BenchOpResult`` so callers don't have to parse
    stdout / exit-code conventions in every site.
  - Never raises on non-zero exit codes — the result carries
    ``ok=False`` + ``stderr`` so the caller can audit + return a
    sensible HTTP response. (Process spawn failure IS exceptional and
    DOES raise.)

Phase 2 mutation operations (``create_site``, ``drop_site``,
``backup_site``, ``restore_site``) land in PR #1B alongside the
Valkey lock primitive — they need cross-call serialization that
``list_sites`` does not.

ADR refs:
  - ADR-0012 §3: bench command surface (Press logic mapped to k8s)
  - ADR-0017 §3.1: agent endpoint surface for Phase 2
"""

from __future__ import annotations

import shlex
import subprocess  # noqa: S404 — intentional; we run trusted internal commands
from dataclasses import dataclass
from typing import Callable, Sequence


@dataclass(frozen=True)
class BenchOpResult:
    """Outcome of one ``bench`` invocation.

    ``ok``: exit code was 0. ``stdout`` / ``stderr``: captured streams.
    ``cmd``: the command we ran (for audit). ``duration_ms``: wall
    clock the operation took.
    """

    ok: bool
    cmd: tuple[str, ...]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int


Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(cmd: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    """Production runner — ``subprocess.run`` with a hard timeout.

    The timeout is per-call generous (5 minutes) because some bench
    operations (``new-site``, ``restore``) genuinely take that long.
    ``list-sites`` returns instantly; the same timeout doesn't hurt
    it.
    """
    return subprocess.run(  # noqa: S603 — cmd is constructed by trusted internal callers
        list(cmd),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _run(cmd: Sequence[str], runner: Runner) -> BenchOpResult:
    import time as _time  # local import keeps the module's import surface flat

    started = _time.monotonic()
    proc = runner(cmd)
    elapsed_ms = int((_time.monotonic() - started) * 1000)
    return BenchOpResult(
        ok=(proc.returncode == 0),
        cmd=tuple(cmd),
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        exit_code=proc.returncode,
        duration_ms=elapsed_ms,
    )


def list_sites(*, runner: Runner = _default_runner) -> tuple[BenchOpResult, list[str]]:
    """List every site hosted on this bench.

    Wraps ``bench list-sites``, which prints one site FQDN per line
    on stdout (Frappe ≥13). Returns the raw result + the parsed
    site list. On failure, the site list is empty and the caller
    should consult ``result.ok`` / ``result.stderr``.

    Frappe's ``bench list-sites`` also includes administrative
    files like ``apps.txt`` in some older versions; we filter to
    entries that look like FQDNs (contain a dot, no spaces, no
    leading dot). Conservative — if a real site name fails the
    filter, we'd rather miss it than return junk.
    """
    result = _run(["bench", "list-sites"], runner)
    if not result.ok:
        return result, []

    sites: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("."):
            continue
        if " " in line or "\t" in line:
            continue
        if "." not in line:
            # Frappe sites are FQDN-shaped (acme.homelab.local); a
            # bare slug without a dot is almost certainly noise from
            # the bench output preamble.
            continue
        sites.append(line)
    return result, sites


def format_cmd_for_audit(cmd: Sequence[str]) -> str:
    """Render a command tuple for human-readable audit logs.

    Uses ``shlex.join`` so any argument that contains a space or
    quote shows up correctly. We never embed secrets in bench
    arguments today, but if that ever changes, callers should
    redact before passing to this function.
    """
    return shlex.join(list(cmd))
