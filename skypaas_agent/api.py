"""Whitelisted Frappe endpoints reachable from the SkyEngPro Cloud
control plane.

Endpoints in 0.3.0:

  - ``login_via_token`` (PR-C, 0.1.0) — Login-as-Admin signed-URL
    per ADR-0013. Auth: ``LoginPayload`` HMAC token. Sync.

  - ``list_sites`` (PR #1A, 0.2.0) — read-only listing of sites,
    consumed by the reconcile loop per ADR-0017 §6.1. Auth:
    ``OperationPayload(op="list_sites")``. Sync.

  - ``create_site`` / ``drop_site`` / ``backup_site`` /
    ``restore_site`` (PR #1B, 0.3.0) — mutating bench operations.
    Async: return ``{job_id, state: "pending"}`` immediately; work
    runs in a background ``frappe.enqueue`` worker that acquires
    the per-bench Valkey lock (``locks.acquire_bench_lock``) before
    invoking the bench CLI. Auth: ``OperationPayload`` bound to the
    matching ``op``.

  - ``get_job`` (PR #1B, 0.3.0) — poll a job's terminal state. Auth:
    ``OperationPayload(op="get_job")``. Sync.

Every endpoint shares the per-tenant HMAC secret from
``site_config.json:skypaas_agent_hmac_secret``. Failures return flat
JSON errors (never Frappe's HTML traceback) so the dashboard can
render useful messages.

Audit: every call — successful or not — is recorded as a
``skypaas_agent.<op>.<outcome>`` Frappe activity log entry. The
control plane ALSO emits its own event when it mints the token;
the two timelines reconcile during incident review.
"""

from __future__ import annotations

from typing import Any

from . import bench_ops, jobs, locks
from .tokens import TokenError, verify, verify_operation

# Conditional whitelist decorator. In production, Frappe loads this
# module after `import frappe` is already valid, so `frappe.whitelist`
# is the real decorator. In unit tests, Frappe isn't on PYTHONPATH at
# module-import time (test fixtures install a stub `frappe` into
# sys.modules per-test). The fallback `_whitelist` is a no-op so the
# module imports cleanly in both worlds; tests that exercise endpoint
# behavior monkey-patch `frappe` AFTER import via sys.modules.
try:
    import frappe as _frappe_for_decorator  # noqa: PLC0415 — module-import time decorator
    _whitelist = _frappe_for_decorator.whitelist
except (ImportError, AttributeError):
    def _whitelist(**_kwargs):
        return lambda f: f


@_whitelist(allow_guest=True)
def login_via_token(token: str = "", next: str = "/app"):  # noqa: A002 — Frappe-style kwarg name
    """The whitelisted endpoint. `@_whitelist(allow_guest=True)` above
    is `frappe.whitelist` in production and a no-op in tests. The body
    verifies the HMAC token + maps the embedded user identity to a
    Frappe session via `login_manager.login_as`."""
    import frappe  # noqa: PLC0415 — imported lazily so unit tests can stub

    site = frappe.local.site
    secret_hex = frappe.local.conf.get("skypaas_agent_hmac_secret")
    if not secret_hex:
        _audit("agent_misconfigured", site=site, reason="hmac_secret_missing")
        frappe.local.response["http_status_code"] = 500
        return {"error": "agent_misconfigured"}

    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError:
        _audit("agent_misconfigured", site=site, reason="hmac_secret_not_hex")
        frappe.local.response["http_status_code"] = 500
        return {"error": "agent_misconfigured"}

    try:
        payload = verify(token, secret, expected_site=site)
    except TokenError as e:
        _audit("login_rejected", site=site, reason=e.reason)
        frappe.local.response["http_status_code"] = 401
        return {"error": "invalid_token", "reason": e.reason}

    frappe.local.login_manager.login_as(payload.user)
    _audit("login_succeeded", site=site, user=payload.user)

    # Sanitize redirect target — only same-origin relative paths.
    target = next if isinstance(next, str) and next.startswith("/") else "/app"
    frappe.local.response["type"] = "redirect"
    frappe.local.response["location"] = target
    return None


def _audit(kind: str, **fields) -> None:
    """Best-effort audit log entry.

    Calls Frappe's `log_activity` (or falls back to a print so unit tests
    can capture the call without a real Frappe runtime). Never raises —
    audit failure must not block the login response.
    """
    try:
        import frappe  # noqa: PLC0415

        frappe.log_error(  # type: ignore[attr-defined]
            title=f"skypaas_agent.{kind}",
            message=str(fields),
        )
    except Exception:
        pass


# ---------- Phase 2 (ADR-0017) ----------


def _load_secret() -> bytes | None:
    """Read + decode the per-tenant HMAC secret from site_config.json.

    Returns the bytes secret on success or ``None`` if the config is
    missing / malformed (the caller emits an audit event and returns
    500). Keeps the secret-loading logic in one place so the login and
    operation endpoints don't drift.
    """
    import frappe  # noqa: PLC0415

    secret_hex = frappe.local.conf.get("skypaas_agent_hmac_secret")
    if not secret_hex:
        return None
    try:
        return bytes.fromhex(secret_hex)
    except ValueError:
        return None


@_whitelist(allow_guest=True)
def list_sites(token: str = ""):
    """Return every Frappe site hosted on this bench.

    Auth: HMAC ``OperationPayload`` with ``op="list_sites"``, bound to
    this site's FQDN. The dashboard's reconcile loop calls this every
    ~30s per ADR-0017 §6.1.

    Response shape on success::

        {
            "ok": true,
            "sites": ["acme-prod.homelab.local", "acme-staging.homelab.local"],
            "duration_ms": 47
        }

    On rejection::

        {"error": "invalid_token", "reason": "<enum>"}  # 401
        {"error": "agent_misconfigured"}                # 500
        {"error": "bench_failed", "stderr": "..."}      # 502 (bench CLI failed)
    """
    import frappe  # noqa: PLC0415

    site = frappe.local.site

    secret = _load_secret()
    if secret is None:
        _audit("list_sites.misconfigured", site=site, reason="hmac_secret_missing_or_not_hex")
        frappe.local.response["http_status_code"] = 500
        return {"error": "agent_misconfigured"}

    try:
        verify_operation(token, secret, expected_site=site, expected_op="list_sites")
    except TokenError as e:
        _audit("list_sites.rejected", site=site, reason=e.reason)
        frappe.local.response["http_status_code"] = 401
        return {"error": "invalid_token", "reason": e.reason}

    result, sites = bench_ops.list_sites()
    if not result.ok:
        _audit(
            "list_sites.bench_failed",
            site=site,
            exit_code=result.exit_code,
            stderr=result.stderr[:500],
        )
        frappe.local.response["http_status_code"] = 502
        return {"error": "bench_failed", "stderr": result.stderr.strip()[:500]}

    _audit("list_sites.ok", site=site, count=len(sites), duration_ms=result.duration_ms)
    return {"ok": True, "sites": sites, "duration_ms": result.duration_ms}


# ---------- Phase 2 PR #1B: site mutations + get_job ----------


def _authorize(token: str, expected_op: str) -> tuple[bytes | None, dict | None]:
    """Run the per-endpoint auth dance: load secret, verify token.

    Returns ``(secret, None)`` on success or ``(None, error_dict)``
    on failure. Sets ``http_status_code`` on the Frappe response so
    the dashboard receives a useful status code without the endpoint
    body needing to repeat itself.
    """
    import frappe  # noqa: PLC0415

    site = frappe.local.site
    secret = _load_secret()
    if secret is None:
        _audit(f"{expected_op}.misconfigured", site=site, reason="hmac_secret_missing_or_not_hex")
        frappe.local.response["http_status_code"] = 500
        return None, {"error": "agent_misconfigured"}

    try:
        verify_operation(token, secret, expected_site=site, expected_op=expected_op)
    except TokenError as e:
        _audit(f"{expected_op}.rejected", site=site, reason=e.reason)
        frappe.local.response["http_status_code"] = 401
        return None, {"error": "invalid_token", "reason": e.reason}
    return secret, None


def _enqueue(method_name: str, **kwargs: Any) -> None:
    """Production-side async dispatch via ``frappe.enqueue``.

    Tests stub ``frappe.enqueue`` to invoke the target synchronously;
    the api layer is unchanged. The ``method_name`` is the dotted
    path Frappe's RQ worker resolves (``skypaas_agent.api._run_<op>_job``).
    """
    import frappe  # noqa: PLC0415

    frappe.enqueue(method_name, queue="default", **kwargs)


def _run_lock_protected(
    job_id: str,
    op_name: str,
    work: Any,
) -> None:
    """Shared worker body — acquire lock, transition state, run op,
    record terminal state.

    ``work`` is a callable returning ``BenchOpResult``. The worker
    handles every failure mode (lock busy, lock unavailable, bench
    failure, exception) by updating the job state via the registry.
    """
    registry = jobs.get_registry()
    registry.start(job_id)
    try:
        client = locks.get_valkey_client()
        if client is None:
            registry.fail(job_id, error="valkey_unavailable: no client configured")
            _audit(f"{op_name}.failed", job_id=job_id, reason="valkey_unavailable")
            return
        try:
            with locks.acquire_bench_lock(client):
                result = work()
        except locks.LockBusyError as e:
            registry.fail(job_id, error=f"lock_busy: {e}")
            _audit(f"{op_name}.failed", job_id=job_id, reason="lock_busy")
            return
        except locks.LockUnavailableError as e:
            registry.fail(job_id, error=f"valkey_unavailable: {e}")
            _audit(f"{op_name}.failed", job_id=job_id, reason="valkey_unavailable")
            return

        if not result.ok:
            registry.fail(job_id, error=result.stderr.strip()[:500] or f"exit {result.exit_code}")
            _audit(
                f"{op_name}.bench_failed",
                job_id=job_id,
                exit_code=result.exit_code,
                stderr=result.stderr[:200],
            )
            return

        # Success — the work() callable returns a result dict via
        # closure; the bench_ops.* result is just the call outcome.
        registry.succeed(
            job_id, result={"cmd_duration_ms": result.duration_ms, "exit_code": result.exit_code}
        )
        _audit(f"{op_name}.ok", job_id=job_id, duration_ms=result.duration_ms)
    except Exception as e:  # pragma: no cover — defensive
        registry.fail(job_id, error=f"unexpected: {type(e).__name__}: {e}")
        _audit(f"{op_name}.exception", job_id=job_id, error=str(e))


def _enqueue_simple_job(op: str, site: str, work_method: str, **work_kwargs: Any) -> dict:
    """Common boilerplate for mutation endpoints: create the job,
    enqueue the worker, return ``{job_id, state}``.

    The response captures ``state`` BEFORE the enqueue dispatch — in
    production this doesn't matter because enqueue is async (RQ
    worker, separate process); in tests where enqueue runs sync,
    capturing first keeps the response shape consistent ("pending"
    on enqueue, not "succeeded" or "failed").
    """
    record = jobs.get_registry().create(op=op, site=site)
    response = {"job_id": record.job_id, "state": record.state.value}
    _audit(f"{op}.queued", site=site, job_id=record.job_id)
    _enqueue(work_method, job_id=record.job_id, **work_kwargs)
    return response


# ---------- create_site ----------


def create_site(
    token: str = "",
    site_name: str = "",
    admin_email: str = "",
    admin_password: str = "",
    install_apps: str = "erpnext",
    mariadb_root_password: str = "",
):
    """Provision a new Frappe site asynchronously.

    Body params:
      - ``site_name``: FQDN-shaped slug, e.g. ``acme-prod.homelab.local``
      - ``admin_email``: Frappe Administrator's email
      - ``admin_password``: ≥12 chars
      - ``install_apps``: comma-separated app names (default ``erpnext``)
      - ``mariadb_root_password``: bench root creds for the new site DB

    Returns ``202 {job_id, state: "pending"}``. Poll ``get_job`` for
    completion. Errors: 401 (token), 422 (validation), 500 (config).
    """
    secret, err = _authorize(token, expected_op="create_site")
    if err is not None:
        return err

    import frappe  # noqa: PLC0415

    if not site_name or "." not in site_name or " " in site_name:
        frappe.local.response["http_status_code"] = 422
        return {"error": "invalid_site_name"}
    if not admin_email or "@" not in admin_email:
        frappe.local.response["http_status_code"] = 422
        return {"error": "invalid_admin_email"}
    if not admin_password or len(admin_password) < 12:
        frappe.local.response["http_status_code"] = 422
        return {"error": "invalid_admin_password"}

    apps = tuple(a.strip() for a in install_apps.split(",") if a.strip()) or ("erpnext",)
    frappe.local.response["http_status_code"] = 202
    return _enqueue_simple_job(
        op="create_site",
        site=frappe.local.site,
        work_method="skypaas_agent.api._run_create_site_job",
        site_name=site_name,
        admin_email=admin_email,
        admin_password=admin_password,
        install_apps_csv=",".join(apps),
        mariadb_root_password=mariadb_root_password or None,
    )


def _run_create_site_job(
    job_id: str,
    site_name: str,
    admin_email: str,
    admin_password: str,
    install_apps_csv: str = "erpnext",
    mariadb_root_password: str | None = None,
) -> None:
    """Background worker for ``create_site``. Registered as a target
    of ``frappe.enqueue`` — the dotted path is referenced from
    :func:`create_site`."""
    apps = tuple(a.strip() for a in install_apps_csv.split(",") if a.strip())
    _run_lock_protected(
        job_id,
        op_name="create_site",
        work=lambda: bench_ops.create_site(
            site_name,
            admin_email=admin_email,
            admin_password=admin_password,
            install_apps=apps,
            mariadb_root_password=mariadb_root_password,
        ),
    )


# ---------- drop_site ----------


def drop_site(token: str = "", site_name: str = ""):
    """Tear down a Frappe site asynchronously.

    Body: ``site_name``. Returns ``202 {job_id, state}``.
    """
    secret, err = _authorize(token, expected_op="drop_site")
    if err is not None:
        return err

    import frappe  # noqa: PLC0415

    if not site_name or "." not in site_name or " " in site_name:
        frappe.local.response["http_status_code"] = 422
        return {"error": "invalid_site_name"}

    frappe.local.response["http_status_code"] = 202
    return _enqueue_simple_job(
        op="drop_site",
        site=frappe.local.site,
        work_method="skypaas_agent.api._run_drop_site_job",
        site_name=site_name,
    )


def _run_drop_site_job(job_id: str, site_name: str) -> None:
    _run_lock_protected(
        job_id,
        op_name="drop_site",
        work=lambda: bench_ops.drop_site(site_name),
    )


# ---------- backup_site ----------


def backup_site(token: str = "", site_name: str = "", with_files: str = "true"):
    """Run ``bench backup`` asynchronously.

    Body: ``site_name``, ``with_files`` (string "true"/"false" since
    Frappe passes form-dict values as strings). Returns ``202 {job_id, state}``.
    """
    secret, err = _authorize(token, expected_op="backup_site")
    if err is not None:
        return err

    import frappe  # noqa: PLC0415

    if not site_name or "." not in site_name or " " in site_name:
        frappe.local.response["http_status_code"] = 422
        return {"error": "invalid_site_name"}

    wf = with_files not in ("false", "False", "0", "")
    frappe.local.response["http_status_code"] = 202
    return _enqueue_simple_job(
        op="backup_site",
        site=frappe.local.site,
        work_method="skypaas_agent.api._run_backup_site_job",
        site_name=site_name,
        with_files=wf,
    )


def _run_backup_site_job(job_id: str, site_name: str, with_files: bool = True) -> None:
    _run_lock_protected(
        job_id,
        op_name="backup_site",
        work=lambda: bench_ops.backup_site(site_name, with_files=with_files),
    )


# ---------- restore_site ----------


def restore_site(
    token: str = "",
    site_name: str = "",
    backup_path: str = "",
    public_files_path: str = "",
    private_files_path: str = "",
    admin_password: str = "",
    mariadb_root_password: str = "",
):
    """Restore a Frappe site from a backup asynchronously.

    Body: ``site_name``, ``backup_path`` (database dump), optional
    file-tarball paths + admin/db password overrides. Returns
    ``202 {job_id, state}``.
    """
    secret, err = _authorize(token, expected_op="restore_site")
    if err is not None:
        return err

    import frappe  # noqa: PLC0415

    if not site_name or "." not in site_name or " " in site_name:
        frappe.local.response["http_status_code"] = 422
        return {"error": "invalid_site_name"}
    if not backup_path:
        frappe.local.response["http_status_code"] = 422
        return {"error": "missing_backup_path"}

    frappe.local.response["http_status_code"] = 202
    return _enqueue_simple_job(
        op="restore_site",
        site=frappe.local.site,
        work_method="skypaas_agent.api._run_restore_site_job",
        site_name=site_name,
        backup_path=backup_path,
        public_files_path=public_files_path or None,
        private_files_path=private_files_path or None,
        admin_password=admin_password or None,
        mariadb_root_password=mariadb_root_password or None,
    )


def _run_restore_site_job(
    job_id: str,
    site_name: str,
    backup_path: str,
    public_files_path: str | None = None,
    private_files_path: str | None = None,
    admin_password: str | None = None,
    mariadb_root_password: str | None = None,
) -> None:
    _run_lock_protected(
        job_id,
        op_name="restore_site",
        work=lambda: bench_ops.restore_site(
            site_name,
            backup_path,
            public_files_path=public_files_path,
            private_files_path=private_files_path,
            admin_password=admin_password,
            mariadb_root_password=mariadb_root_password,
        ),
    )


# ---------- get_job ----------


def get_job(token: str = "", job_id: str = ""):
    """Return a job's current state.

    Auth: ``OperationPayload(op="get_job")``. Returns the job's
    full serialized record; the control plane polls this every
    ~2 s while the job is non-terminal.
    """
    secret, err = _authorize(token, expected_op="get_job")
    if err is not None:
        return err

    import frappe  # noqa: PLC0415

    if not job_id:
        frappe.local.response["http_status_code"] = 422
        return {"error": "missing_job_id"}

    record = jobs.get_registry().get(job_id)
    if record is None:
        frappe.local.response["http_status_code"] = 404
        return {"error": "job_not_found"}

    return record.to_dict()
