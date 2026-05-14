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

Read-only operations (``list_sites``) need no cross-call lock.
Mutation operations (``create_site``, ``drop_site``, ``backup_site``,
``restore_site``) MUST be wrapped in ``locks.acquire_bench_lock`` by
their caller — they mutate the bench's shared filesystem state. The
api layer enforces this; ``bench_ops`` does not lock internally so
unit tests can exercise pure logic.

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
    quote shows up correctly. Redacts known-sensitive flags
    (``--admin-password``, ``--mariadb-root-password``,
    ``--db-password``, ``--db-root-password``) by replacing the
    value with ``<REDACTED>``. Callers extending the set of bench
    commands should keep the redactable-flags allow-list in sync.
    """
    redactable_flags = {
        "--admin-password",
        "--mariadb-root-password",
        "--db-password",
        "--db-root-password",
    }
    redacted: list[str] = []
    i = 0
    while i < len(cmd):
        arg = cmd[i]
        if "=" in arg and any(arg.startswith(f + "=") for f in redactable_flags):
            flag = arg.split("=", 1)[0]
            redacted.append(f"{flag}=<REDACTED>")
        elif arg in redactable_flags and i + 1 < len(cmd):
            redacted.append(arg)
            redacted.append("<REDACTED>")
            i += 1
        else:
            redacted.append(arg)
        i += 1
    return shlex.join(redacted)


def create_site(
    site_name: str,
    *,
    admin_email: str,
    admin_password: str,
    install_apps: Sequence[str] = ("erpnext",),
    mariadb_root_password: str | None = None,
    runner: Runner = _default_runner,
) -> BenchOpResult:
    """Provision a new Frappe site via ``bench new-site``.

    Trade-off accepted: ``--admin-password`` is passed on the command
    line, briefly visible to ``ps`` inside the bench pod. Within the
    pod's user boundary (agent runs as the same uid as bench), this
    matches the pattern Frappe Press uses in production. Audit logs
    redact via :func:`format_cmd_for_audit`. A future hardening could
    pipe the password via ``--admin-password-stdin`` once Frappe
    supports it.

    Callers MUST wrap this in ``locks.acquire_bench_lock`` — concurrent
    ``bench new-site`` invocations corrupt ``currentsite.txt``.
    """
    cmd: list[str] = [
        "bench",
        "new-site",
        site_name,
        "--admin-email",
        admin_email,
        "--admin-password",
        admin_password,
    ]
    for app in install_apps:
        cmd.extend(["--install-app", app])
    if mariadb_root_password:
        cmd.extend(["--mariadb-root-password", mariadb_root_password])
    return _run(cmd, runner)


def drop_site(
    site_name: str,
    *,
    force: bool = True,
    no_backup: bool = True,
    runner: Runner = _default_runner,
) -> BenchOpResult:
    """Tear down a site via ``bench drop-site``.

    Defaults: ``--force`` to skip the interactive confirmation (we are
    a programmatic caller), ``--no-backup`` because the control plane
    handles backup orchestration separately (ADR-0017 §5; backups go
    to MinIO, not a per-bench file the drop-site command would
    produce).

    Callers MUST wrap this in ``locks.acquire_bench_lock``.
    """
    cmd: list[str] = ["bench", "drop-site", site_name]
    if force:
        cmd.append("--force")
    if no_backup:
        cmd.append("--no-backup")
    return _run(cmd, runner)


def backup_site(
    site_name: str,
    *,
    with_files: bool = True,
    runner: Runner = _default_runner,
) -> BenchOpResult:
    """Run ``bench --site <name> backup``.

    Produces files in ``sites/<site>/private/backups/`` on the bench
    pod's PVC. The control plane reads + uploads them to MinIO per
    ADR-0017 §5. ``with_files=True`` adds the public + private files
    tarball, not just the database dump.

    Callers MUST wrap this in ``locks.acquire_bench_lock``. While
    ``bench backup`` is theoretically per-site, in practice it
    serialises on the MariaDB ``FLUSH TABLES`` call; concurrent
    backups on the same bench's sites can race against that lock.
    The bench-wide lock is the cheaper guarantee.

    Future hardening (PR #1C): parse the stdout to extract the
    backup file paths so the control plane doesn't need an
    out-of-band ``ls`` of the backup directory.
    """
    cmd: list[str] = ["bench", "--site", site_name, "backup"]
    if with_files:
        cmd.append("--with-files")
    return _run(cmd, runner)


def restore_site(
    site_name: str,
    backup_path: str,
    *,
    public_files_path: str | None = None,
    private_files_path: str | None = None,
    admin_password: str | None = None,
    mariadb_root_password: str | None = None,
    runner: Runner = _default_runner,
) -> BenchOpResult:
    """Restore a site from a backup via ``bench --site <name> restore``.

    ``backup_path`` is the database dump. Optional file tarballs are
    restored with ``--with-public-files`` / ``--with-private-files``.

    Callers MUST wrap this in ``locks.acquire_bench_lock``. Per
    SRE brief Q3 (ADR-0017 §10.2 open question): we don't yet have
    a real-bench verification of whether Frappe's restore locks the
    whole bench or just the target site. The bench-wide lock is the
    conservative default; if a real-bench test in PR #1C shows the
    bench-wide lock is unnecessary, we can downgrade.
    """
    cmd: list[str] = ["bench", "--site", site_name, "restore", backup_path]
    if public_files_path:
        cmd.extend(["--with-public-files", public_files_path])
    if private_files_path:
        cmd.extend(["--with-private-files", private_files_path])
    if admin_password:
        cmd.extend(["--admin-password", admin_password])
    if mariadb_root_password:
        cmd.extend(["--mariadb-root-password", mariadb_root_password])
    return _run(cmd, runner)
