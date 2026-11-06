# ADR-0004: Identity provider: Zitadel Cloud (EU), conditional

Status: conditionally accepted, pending vendor verification

M0 uses only a local mock OIDC provider. The application speaks standard OIDC (`openid-client`); roles and permissions live in our own database. Switching IdP is configuration plus a user migration.

Verification before M1 (owner + DPO/legal):
1. Full subprocessor list (incl. e-mail/SMS for MFA, support tooling) and the regions per subprocessor
2. Support access policy: who, from where, with what approval and logging
3. DPA + SCCs; transfer basis for US subprocessors (Google Cloud infrastructure is listed)
4. SLA, incident notification times (DORA input), exit and data-export terms
5. Current licence terms for self-hosting (exit strategy)
6. Price at around 50 tenants with SSO
7. Availability of `amr`/`acr` claims for MFA enforcement
