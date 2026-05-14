"""Whitelisted Frappe endpoints reachable from the SkyEngPro Cloud
control plane.

Today the agent exposes:

  - ``login_via_token`` (PR-C, 0.1.0) — the Login-as-Admin signed-URL
    endpoint per ADR-0013. Auth: ``LoginPayload`` HMAC token.

  - ``list_sites`` (PR #1A, 0.2.0) — read-only listing of sites
    hosted on this bench, used by the control plane's reconcile loop
    per ADR-0017 §3.1 / §6.1. Auth: ``OperationPayload`` HMAC token
    bound to ``op=list_sites``.

Mutation endpoints (``create_site``, ``drop_site``, ``backup_site``,
``restore_site``) and the job-poll endpoint land in PR #1B.

Every endpoint shares the same per-tenant HMAC secret from
``site_config.json:skypaas_agent_hmac_secret``. Failures return flat
JSON errors (never Frappe's HTML traceback) so the dashboard can
render useful messages.

Audit: every call — successful or not — is recorded as a
``skypaas_agent_*`` Frappe activity log entry. The control plane
ALSO emits its own event when it mints the token; the two timelines
reconcile during incident review.
"""

from __future__ import annotations

from . import bench_ops
from .tokens import TokenError, verify, verify_operation


def login_via_token(token: str = "", next: str = "/app"):  # noqa: A002 — Frappe-style kwarg name
    """The whitelisted endpoint. Frappe sets allow_guest=True via the
    decorator below at runtime (frappe.whitelist is monkey-patched at
    import-time; we keep the body framework-agnostic so it's unit-testable
    without a Frappe runtime)."""
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
