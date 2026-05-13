"""SkyEngPro tenant-side agent.

Installed inside each customer's Frappe bench. Exposes one whitelisted
endpoint, ``/api/method/skypaas_agent.api.login_via_token``, which
accepts a short-lived HMAC-signed token issued by the SkyEngPro Cloud
control plane and logs the operator in as the named Frappe user
(typically ``Administrator``) without ever transmitting a password.

See ADR-0013 (Credentials never in UI) for the binding rule this agent
implements, and ADR-0012 (ERPNext deploy via Press logic) for the
broader Phase 2 Agent architecture this is one verb of.
"""

__version__ = "0.1.0"
