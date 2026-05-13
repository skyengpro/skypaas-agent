# How the `skypaas_agent` Frappe app works

> Audience: operators of SkyEngPro Cloud who need to understand how the
> "Login as Admin" button in the dashboard authenticates without ever
> sending or displaying a password. See [ADR-0013](../decisions/0013-credentials-never-in-ui.md)
> for the binding policy this implements.

## One paragraph

`skypaas_agent` is a tiny Frappe app installed inside every tenant's
bench. It exposes one whitelisted endpoint —
`/api/method/skypaas_agent.api.login_via_token` — that accepts a short-
lived HMAC-signed token issued by the SkyEngPro Cloud control plane,
verifies it, and logs the operator in as the named Frappe user
(typically `Administrator`). No password is ever transmitted; nothing
sensitive is displayed in the dashboard UI.

## Why a separate agent

Vanilla Frappe has no native "give me a one-shot login URL" endpoint.
The `/api/method/login` endpoint accepts `usr` + `pwd` only. To get the
Frappe-Cloud-style signed-URL UX while honoring ADR-0013 (no password
in UI), we need a tiny piece of trusted code running inside each
tenant. That's `skypaas_agent`.

## Token format

```
<base64url(json_payload)>.<hex(hmac_sha256(per_tenant_secret, payload))>
```

The payload is JSON with three fields:

| Field | Type | Meaning |
|-------|------|---------|
| `user` | string | Frappe user to log in as. Almost always `Administrator`. |
| `site` | string | Target site FQDN. Prevents a token minted for tenant A from unlocking tenant B even if their secrets happen to match. |
| `exp` | int | Absolute Unix timestamp when the token expires. |

Default TTL: **60 seconds**. Hard maximum: **300 seconds** (enforced by
the verifier — defense against a misconfigured control plane issuing
hour-long tokens).

We deliberately do **not** use JWT — `skypaas_agent` must run inside a
Frappe bench with no extra runtime dependencies. stdlib `hmac` +
`base64` is sufficient and audit-easy.

## Per-tenant secret

Each tenant gets its own 32-byte random HMAC secret at provision time.
Stored in:

- **Control plane** — KeePassXC vault, behind the secret gateway, at
  `kp://tenants/<slug>/agent_hmac` (see [ADR-0011](../decisions/0011-secret-management-v1.md)).
- **Tenant side** — `site_config.json` field `skypaas_agent_hmac_secret`
  (hex-encoded). Injected by the Helm chart from a K8s Secret in the
  tenant's namespace; never visible outside the pod.

Compromise of one tenant's secret unlocks **only that tenant**. There
is no global key.

## End-to-end flow

1. Operator clicks **Login as Admin** in the dashboard.
2. Dashboard POSTs to `skypaas` control plane: `/api/instances/<id>/login_as_admin`.
3. Control plane:
   - Resolves the per-tenant secret via the gateway.
   - Builds a payload `{user: "Administrator", site: "<fqdn>", exp: now+60}`.
   - Signs with the secret.
   - Logs a `credential.used` audit event (operator, tenant, instance).
   - Returns `{redirect_url: "https://<fqdn>/api/method/skypaas_agent.api.login_via_token?token=<signed>"}`.
4. Dashboard opens that URL in a new browser tab.
5. Inside the tenant:
   - Agent reads the HMAC secret from `site_config.json`.
   - Calls `tokens.verify(token, secret, expected_site=frappe.local.site)`.
   - If valid: calls `frappe.local.login_manager.login_as(user)`, sets
     the session cookie, redirects to `/app` (the Frappe Desk).
   - Logs a tenant-side `skypaas_agent.login_succeeded` audit entry.
6. Operator's browser is now authenticated against the tenant site,
   without the password ever leaving the gateway or appearing in any
   UI.

## Failure modes the verifier rejects

| Reason | Trigger | HTTP |
|--------|---------|------|
| `malformed` | Bad format, bad base64, missing fields | 401 |
| `bad_signature` | HMAC mismatch (constant-time compared) | 401 |
| `expired` | `exp ≤ now` | 401 |
| `too_long_ttl` | `exp - now > 300s` (refuses to honor over-long tokens) | 401 |
| `wrong_site` | Token's `site` field doesn't match `frappe.local.site` | 401 |
| `agent_misconfigured` | Secret missing or non-hex in `site_config.json` | 500 |

Every rejection is audit-logged on the tenant side with its reason,
so an incident-response timeline can reconcile control-plane events
against tenant events independently.

## What this PR (PR-C1) actually ships

- The Frappe app code at `skypaas_agent/`
- 25 unit tests covering signing, verification, audit emission, and
  the open-redirect guard
- This document

What it does **NOT** ship yet (later PRs):

- PR-C2: chart wiring that installs the agent on every tenant + injects
  the per-tenant secret
- PR-C3: control-plane endpoint that mints + signs tokens
- PR-C4: dashboard button enable

The agent is testable in isolation today. The button stays disabled
until PR-C4.

## Adding a new endpoint to the agent later

The agent is the natural home for future tenant-side verbs that the
control plane needs to call (backup trigger, app install, drop-site,
…). Pattern:

1. Add the function to `skypaas_agent/api.py`. Use `@frappe.whitelist`
   if it's reachable from outside the pod, no decorator if it's only
   for in-pod use.
2. Authenticate via the same HMAC-token primitive — every verb gets a
   signed payload, no exceptions.
3. Add tests in `skypaas_agent/tests/`.
4. Document the verb in this how-to.
