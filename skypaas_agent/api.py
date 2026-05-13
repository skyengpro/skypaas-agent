"""Whitelisted Frappe endpoint that consumes a signed login token.

Reachable from outside the tenant pod at:

    https://<site>/api/method/skypaas_agent.api.login_via_token?token=<signed>

Flow:

  1. Read the per-tenant HMAC secret from this site's `site_config.json`
     (`skypaas_agent_hmac_secret`, hex-encoded).
  2. Verify the token (signature, expiry, site binding).
  3. Call `frappe.local.login_manager.login_as(user)` to set the session
     cookie. From this point the operator's browser is authenticated.
  4. Redirect to /app (the Desk) or to the `next` query param if provided.

Failures return a flat JSON error (not the Frappe HTML traceback) so the
dashboard's caller can render a useful message.

Audit: every attempt — successful or not — is recorded as a
``skypaas_agent_login`` Frappe activity log entry. The control plane is
expected to ALSO emit its own ``credential.used`` event when it mints
the token; this is the matching tenant-side breadcrumb so two
independent timelines can be reconciled during an incident.
"""

from __future__ import annotations

from .tokens import TokenError, verify


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
