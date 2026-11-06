# M1: Identity and tenancy. Acceptance checklist (rev. 2)

Status: **approved at design level; NOT authorized for implementation.**

Prerequisites before implementation starts:
1. Explicit approval from the owner.
2. Zitadel verification items V3, V6, V7, V11 and V12 ([report](../reports/zitadel-verification.md)) answered satisfactorily, or an explicit decision to start against a Zitadel test instance while the contract is still open.

Principle: as simple as possible. Each control below is one function, one table or one constraint. **Not in M1:** SCIM provisioning, a policy engine (OpenFGA/Cedar), a workflow engine, our own e-mail delivery (see D2), and the investor portal.

## Design decisions (for approval together with this checklist)

| # | Decision | Rationale |
|---|---|---|
| D1 | **Two assurance levels.** `mfa` is the minimum for everyone. `phishing_resistant` can be switched on per tenant. Derived from the ID-token `amr` claim (RFC 8176). | Simple and testable; no generic AAL framework |
| D2 | **Invitation links are not e-mailed by InvestorOS in M1.** The admin copies the link (shown once). | No extra subprocessor (mail provider) and no extra attack surface. Mail delivery comes later as a separate decision |
| D3 | **Federated SSO: Zitadel enforces its own second factor after federation**, unless a tenant explicitly chooses "trust upstream MFA" (not in M1) | Upstream `amr`/`acr` mapping differs per customer IdP and is error-prone |
| D4 | **IAM mutations in the database:** one subset trigger ("you can't hand out what you don't hold") plus a per-tenant advisory lock | Escalation and race conditions are stopped where they can't be bypassed |
| D5 | **Recent authentication for privileged actions:** `auth_time` ≤ 30 minutes for role, grant, SSO and owner changes; otherwise re-login with `max_age` | Limits the damage of a stolen session; one check, not a step-up framework |
| D6 | **Login events go to a global `auth_events` table** (append-only, not visible in the app). Tenant actions go to `audit_events`. IP addresses are stored truncated (/24 IPv4, /48 IPv6). | Security evidence with data minimisation |

## Acceptance criteria

Each criterion has a test ID. "Negative" means the test proves something is refused.

### AC1: OIDC token validation and MFA/assurance
| ID | Criterion | Test |
|---|---|---|
| 1.1 | ID token: signature checked against the issuer's JWKS; **algorithm allowlist RS256/ES256** (`none` and `HS*` refused); `iss` matches exactly; `aud` contains the client ID, and `azp` is checked when there are several audiences; `exp`/`iat`/`nbf` with ≤ 60 s clock skew; `nonce`; `state`; PKCE S256 | negative test for each claim against the mock IdP (wrong alg, expired, wrong aud, wrong iss, missing nonce, replay) |
| 1.2 | `amr` comes **only from the validated ID token**, never from userinfo or the access token | unit |
| 1.3 | `mfa` level: `amr` contains at least one of {`mfa`, `otp`, `hwk`, `swk`, `fido`, `u2f`}. **`sms` alone is not accepted.** `phishing_resistant` level: {`hwk`, `swk`, `fido`, `u2f`} | decision table test of every combination, including missing `amr`, empty `amr`, `["pwd"]`, `["pwd","sms"]` |
| 1.4 | Insufficient assurance → no session, a generic error message, an `auth_events` entry with reason `insufficient_assurance` | negative + audit assert |
| 1.5 | Session stores `amr`, `auth_time` and the assurance level reached. A tenant with `phishing_resistant` is only reachable with a session at that level; otherwise re-login | negative: `mfa` session → `phishing_resistant` tenant refused |
| 1.6 | Federated SSO: a user via a customer IdP without Zitadel MFA → refused; with Zitadel MFA → admitted | E2E against a Zitadel test instance (V7) plus a mock scenario in CI |
| 1.7 | Recent authentication (D5): privileged action with `auth_time` > 30 min → refused and re-login with `max_age` | negative per privileged action |

### AC2: Tenant SSO and identity mapping
| ID | Criterion | Test |
|---|---|---|
| 2.1 | Mapping table `tenant_idp_bindings(tenant_id, issuer, idp_org_id, sso_required)`. The org claim is only trusted from the validated ID token | unit |
| 2.2 | **A verified e-mail domain never grants membership.** Domains are used only to route the login (home realm discovery) | negative: user from a verified domain without membership → no access, no membership created |
| 2.3 | Access to a tenant requires an explicit, active membership **and** (if `sso_required`) a login via the bound org | negative: member logs in via another org or a local account → that tenant refused, other tenants unaffected |
| 2.4 | An org claim from another org with the same e-mail domain → refused | negative |
| 2.5 | Identity link stays `(issuer, subject)`. A second identity for the same user (e.g. moving to SSO) is linked only by an admin action with recent auth, and audited | negative: automatic linking by e-mail does not happen |
| 2.6 | Changing an SSO binding is a privileged action (D5), audited, and revokes active sessions for that tenant | test |

### AC3: Invitations
| ID | Criterion | Test |
|---|---|---|
| 3.1 | Invitation = random 256-bit token (only the hash stored), bound to tenant + normalised e-mail + roles, 72 h, single-use, revocable | unit |
| 3.2 | Inviter can only hand out roles whose permissions they hold themselves (same subset rule as AC4) | negative |
| 3.3 | **Expired** → refused | negative |
| 3.4 | **Reused** (second acceptance, including two simultaneous acceptances) → exactly one succeeds | negative + concurrency test |
| 3.5 | **Forwarded:** accepted by an identity whose verified e-mail (`email_verified=true`) does not match → refused, invitation stays open, audited | negative |
| 3.6 | **Mismatch:** token used for another tenant URL, after the invitation was revoked, or with `email_verified=false` → refused | negative |
| 3.7 | **Existing account:** identity already known → membership added to the existing user, no new user created. Already an active member → idempotent error, no role change | test |
| 3.8 | **Suspended member** invited again → refused (reactivation is a separate, audited action) | negative |
| 3.9 | Acceptance requires a full login meeting AC1. On acceptance the session token rotates | test |
| 3.10 | Unknown or invalid tokens give the same response and timing class as expired ones (no enumeration) | negative |

### AC4: Authorization and privilege escalation
| ID | Criterion | Test |
|---|---|---|
| 4.1 | **Subset rule in the DB (D4):** assigning a role (direct or to a team), adding a member to a team, and adding permissions to a custom role are only allowed if the actor holds all resulting permissions (at that scope) | negative per path |
| 4.2 | **Indirect via teams:** adding yourself or another person to a team that carries a stronger role → refused without the subset | negative |
| 4.3 | **Custom roles:** you can't add a permission you don't hold; you can't change a role assigned to yourself to escalate; system roles stay immutable | negative |
| 4.4 | **Scoped permissions:** a scoped role never grants a tenant-wide permission; scope only on securables in your own tenant; scoped `access.manage` does not exist | negative |
| 4.5 | **Last owner:** you can't remove, suspend or downgrade the last active owner, **including two simultaneous actions** (advisory lock per tenant) | concurrency test: two admins demote each other at the same time → at least one owner remains |
| 4.6 | **Concurrent changes:** a permission withdrawal committed before an action → the action is refused (check and write in the same transaction, enforced by DB policies) | concurrency test |
| 4.7 | You can't suspend yourself or change your own roles | negative |
| 4.8 | Authorization matrix and DB parity extended to custom roles and scoped assignments | generated |

### AC5: Session security
| ID | Criterion | Test |
|---|---|---|
| 5.1 | Rotation on login, invitation acceptance, tenant switch and assurance increase. The old token is invalid immediately | test per trigger |
| 5.2 | Idle 30 min / absolute 12 h (per-tenant tightening possible, never loosening) | test |
| 5.3 | Logout, admin revocation and "sign out everywhere" | test |
| 5.4 | **Suspension of a membership:** that tenant becomes unreachable immediately (pages 404, API 401/404, server actions refused); other tenants stay reachable | E2E + integration |
| 5.5 | **Disabled user:** all sessions invalid immediately | test |
| 5.6 | **Background actions:** `executeAsMember(job)` re-checks membership and permission at execution time; a suspended or withdrawn member → job refused and audited | integration (primitive only; no real jobs in M1) |
| 5.7 | Tenant switch: context comes from the session, never from the request body; after a switch, no data from the previous tenant in the response or cache (`no-store` on tenant pages) | E2E |

### AC6: Audit (with data minimisation)
| ID | Criterion | Test |
|---|---|---|
| 6.1 | **Privileged actions** each produce exactly one audit event in the same transaction: invite / accept / revoke, membership status, role assignment, custom role change, team change, grant change, SSO binding, tenant settings, identity linking | test per action |
| 6.2 | **Access denials** are audited for privileged permissions (`iam.*`, `access.manage`, `securables.manage`, `tenant.settings.manage`) and restricted resources. Ordinary denials and cross-tenant 404s go to the security log only (no tenant audit: that would itself leak information) | test |
| 6.3 | **Sensitive reads** audited: every use of `restricted.oversight`, reading the audit log, exporting member lists | test |
| 6.4 | **Data minimisation:** audit events contain IDs and changed fields, **no** e-mail addresses, names or tokens; IP truncated; a test fails if an audit row contains a raw e-mail pattern or token | negative (pattern scan over all audit rows produced in the test suite) |
| 6.5 | `auth_events` (D6): login success/failure with reason code, MFA failure, invitation failure; append-only; not readable by `ios_app` | test |

### AC7: Negative security tests (cross-cutting)
| ID | Criterion | Test |
|---|---|---|
| 7.1 | **Cross-tenant:** every new table in the generated isolation suite; every new route and server action called with an ID from another tenant → 404, no data | generated |
| 7.2 | **Direct server-action invocation:** every server action is called over HTTP without a session, with a session from another tenant, with insufficient permission, and with a manipulated body (`tenantId`, `membershipId`, `roleId` from another tenant) → refused; no state change | generated from a registry of all actions (a test fails if an action is missing from the registry) |
| 7.3 | **IDOR:** for each resource ID in routes and actions: an ID from the own tenant without rights, from another tenant, and a non-existent ID give the same response | test |
| 7.4 | **Privilege escalation:** the AC4 paths through UI, server actions and direct SQL as `ios_app` | test |
| 7.5 | CSRF: every mutation as a server action or POST with an Origin check; foreign Origin → refused | test |

### AC8: Hygiene (carried over)
| ID | Criterion |
|---|---|
| 8.1 | GitHub Actions pinned to commit SHAs and upgraded to Node 24-compatible versions (CI currently warns about the Node 20 deprecation); Renovate |
| 8.2 | Typed query builder decided (ADR-0006) and applied to new code |
| 8.3 | Structured logging with redaction; no PII or tokens in logs (test) |
| 8.4 | Kernel coverage stays at 100%; isolation suite, authorization matrix and E2E green in CI |
| 8.5 | Test report + security review of the identity flows to the owner; **no M2 before approval** |
