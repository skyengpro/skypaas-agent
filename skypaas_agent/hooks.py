"""Frappe app metadata for skypaas_agent.

Frappe loads this module to learn the app's name, version, and any
DocType hooks. We keep the surface intentionally minimal — this app
exists only for the Login-as-Admin signed-URL flow today.
"""

from __future__ import annotations

app_name = "skypaas_agent"
app_title = "SkyEngPro Agent"
app_publisher = "SkyEngPro"
app_description = (
    "Tenant-side companion for SkyEngPro Cloud: HMAC-verified Login-as-Admin "
    "endpoint (ADR-0013) + Phase 2 site CRUD endpoints (ADR-0017)."
)
app_email = "ops@skyengpro.com"
app_license = "AGPL-3.0-only"
app_version = "0.2.0"

# No DocTypes, no fixtures, no scheduler hooks today. The agent is pure
# code reachable via /api/method/skypaas_agent.api.*.
