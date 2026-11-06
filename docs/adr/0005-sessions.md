# ADR-0005: Server-side sessions, opaque cookie

Status: accepted, implemented in M0

Decision: after OIDC login the application creates its own session. The cookie holds a random 256-bit token; the database stores only its SHA-256. Idle 30 min, absolute 12 h, rotation on login, revocation on logout, suspension or a disabled user. IdP tokens never reach the browser.

Rationale: immediate revocation, tenant switching without a new IdP round-trip, and no dependency on the IdP token format.
