# M1 clarifications (rev. 3): assurance, database identity, immediate revocation

Status: **proposed for approval.** This document replaces D1 and supplements AC1, AC4 and AC5 in [M1-identity.md](../specs/M1-identity.md).

---

## C1. Authentication assurance

### Problem with rev. 2
`amr` is a claim the IdP **asserts about itself**. A single value such as `hwk` or `u2f` does not prove:
- which method was actually phishing-resistant (the first factor may have been a phishable password);
- whether the login was federated (then the upstream IdP determined the method);
- whether Zitadel could have accepted a weaker method under that org's policy.

Rev. 2 classified assurance from loose `amr` values. That was too weak.

### Principle
Assurance = **(1) validated token** + **(2) verified IdP configuration** + **(3) an evidence-based mapping for a pinned Zitadel version**. Anything not demonstrably covered is refused (default deny).

### Policy inputs
| Input | Source | Trusted because |
|---|---|---|
| `iss`, `aud`, `azp`, signature, `exp`/`iat`/`nbf`, `nonce` | ID token | Validated by `openid-client` + algorithm allowlist (AC1.1) |
| `amr` (complete set, not single values) | ID token only | Validated token; interpreted only through the evidence matrix |
| `auth_time` | ID token | Validated token; required (`max_age` is always sent) |
| Org of the user (resource owner) | ID token (reserved Zitadel scope) | Validated token. **V8: claim name and behaviour must be confirmed** |
| Login policy of that org (force MFA, also for federated users? allowed second factors?) | Zitadel Management API, checked when an SSO binding is created and daily afterwards | Read with our own service account. **Configuration drift → tenant blocked + alert** |
| Zitadel version | Zitadel API | The evidence matrix applies to a pinned version |

### Evidence matrix (first deliverable of M1)
Against a Zitadel test instance (synthetic users), we record **for each login method** which claims Zitadel actually issues:

| Method (Zitadel test instance) | Observed `amr` | Level |
|---|---|---|
| password only | to be recorded | **reject** |
| password + TOTP | to be recorded | `mfa` |
| password + SMS OTP | to be recorded | **reject** (SMS not accepted) |
| password + U2F/WebAuthn | to be recorded | `mfa` |
| passkey (passwordless WebAuthn) | to be recorded | `mfa`; candidate for `phishing_resistant` |
| federated IdP, Zitadel MFA forced afterwards | to be recorded (V7) | `mfa` if distinguishable, else reject |
| federated IdP without Zitadel MFA | to be recorded | **reject** |

- The matrix is stored as a versioned table in code (`assurance-matrix.ts`), with the recorded ID-token claims as fixtures.
- CI replays the fixtures.
- A nightly canary login against the test instance compares live claims with the fixtures. A deviation means a Zitadel upgrade changed behaviour, and that is a blocking alert.

### Decision rules
1. **Unknown `amr` combination → reject.** We use exact set matching from the matrix, not "contains X".
2. **`mfa`:** the `amr` set exactly matches an `mfa` row **AND** the org login policy enforces MFA for **all** users, including federated ones, with SMS disabled as a second factor.
3. **`phishing_resistant`: NOT available in M1.** It is only switched on (in a later milestone, with your approval) if all of these hold:
   - (a) the matrix proves that Zitadel issues a distinguishable claim set for a WebAuthn-only login;
   - (b) the org login policy allows **only** passkeys/U2F (no password+OTP, no SMS, no federation);
   - (c) both are confirmed by the canary.

   If Zitadel cannot make that distinction, we **don't** claim the level. That is more honest than a label we can't substantiate.
4. **`auth_time` is required.** Privileged actions need `auth_time` ≤ 30 min (D5). Otherwise re-login with `prompt=login&max_age=0`.
5. The session stores: assurance level, `amr` set, `auth_time`, org ID, matrix version. Each request validates against the session; the token isn't validated again.

### Tests (replace AC1.3/1.5/1.6)
- A1: each matrix row as a fixture → expected level; each **single** value (`hwk`, `u2f`, `swk`, `fido`) in an otherwise unknown set → reject.
- A2: correct `amr` but org policy "force MFA for local users only" → reject.
- A3: correct `amr` but org policy with SMS allowed → reject.
- A4: org policy drift detected → tenant blocked; existing sessions for that tenant invalid.
- A5: missing `auth_time` → reject; old `auth_time` → privileged action refused.
- A6: canary deviation → test fails (staging job, not blocking every PR).

---

## C2. How the database identifies the actor and evaluates permissions

### Problem with M0
In M0, RLS reads `app.membership_id` from a **GUC** set with `set_config`. A GUC is **writable by every session**. Anyone who can execute SQL as `ios_app` can therefore set `app.membership_id` to a colleague's membership and act as them.

The application layer never does that, but the **database itself does not verify it**. Your requirement ("avoid trusting actor identity supplied through arbitrary client-controlled fields") is not met in M0 at database level. This is a real gap and I didn't list it explicitly before. It was buried as "context spoofing" in rls-design §6.

### Solution: DB-verified, session-bound context (minimal)

```
Request ──(session cookie = token)──► app ──► BEGIN
                                             SELECT auth.begin($token, $tenant_slug, 'read'|'write')
                                             ... queries under RLS ...
                                             COMMIT
```

1. **`auth.begin(token, tenant_slug, mode)`**, SECURITY DEFINER, owned by `ios_definer`:
   - computes `sha256(token)` and looks up the session;
   - checks: not revoked, not expired, idle window not exceeded, user active, tenant active, an **active membership** of that user in that tenant, and (if the tenant requires SSO) the session's org matches the binding;
   - writes the result into **`auth.tx_context`**, keyed by `(pg_backend_pid(), transaction_timestamp())`. Columns: user, membership, tenant, session, principal type, `authz_epoch`.
2. **`auth.tx_context` is writable only by `ios_definer`.** `ios_app` and `ios_worker` have no grant on it.
3. **`app.current_tenant()`, `app.current_user_id()` and `app.current_membership()`** become SECURITY DEFINER functions that read **only** `auth.tx_context` for the current backend + transaction. **They no longer read any GUC.** `set_config('app.membership_id', …)` then has no effect at all.
4. **Raw token, not the hash.** The app passes the raw token. The DB stores and compares only hashes. Someone with SQL access as `ios_app` cannot read others' tokens (they aren't stored) and can only "be" an identity whose token they hold. That reduces SQL-level abuse to the attacker's **own** rights.
   - Precondition: query parameters are not logged (`log_statement=none`, `log_parameter_max_length=0`). This is verified in the hosting checklist.
5. **Workers:**
   - `auth.begin_job(job_id, lease)` (only for `session_user = 'ios_worker'`) derives the actor from a **job row** that was written in the user's original transaction with `enqueued_by = app.current_membership()`. The worker cannot choose who to act as; it can only execute existing jobs.
   - `auth.begin_system(job_name)` gives a system principal with only explicitly granted system policies.
6. Policies call the context functions as `(SELECT app.current_tenant())`, evaluated once per statement. Cost: one indexed lookup per statement. **Benchmark is part of M1.**

**Residual risk (explicit).** A fully compromised application server sees tokens in transit and can therefore act as every user who is active at that moment. No database mechanism protects against that. It is covered by hosting hardening, short sessions and monitoring.

### Effective permissions
- Always computed **live in the same transaction** from `role_assignments` ∪ team assignments → `role_permissions`. There is **no cache** of permissions, not in the DB and not across requests.
- In the app, `loadPrincipalAccess()` is loaded per request **inside the same transaction** and discarded after the response.

### Concurrency: no window between check and action
- **`tenant_memberships.authz_epoch`.** Every rights-changing mutation increments the epoch of every affected membership **in the same transaction**: role or team assignment, team membership, custom role permissions, grants, suspension, user disable. A change to a team role bumps all members of that team.
- **Write transactions** (`mode='write'`) take `SELECT … FOR SHARE` on their own membership row in `auth.begin`.
- Effect:
  - A revocation that is in flight waits for running write actions.
  - Write actions that start after the revocation commits see the new rights.
  - So every write either finishes **entirely before** or starts **entirely after** a revocation. There is no TOCTOU window.
  - Read requests take no lock. A read that started before the commit may still finish with the old rights. That is equivalent to the request arriving a few milliseconds earlier, and is acceptable.
- **IAM mutations** additionally take `pg_advisory_xact_lock(tenant)`. Two concurrent IAM changes in the same tenant are serialized, which blocks write skew such as two admins demoting each other.

### Team-based and indirect escalation (DB-enforced, D4)
A trigger on `role_assignments`, `team_members`, `role_permissions` and `securable_grants` computes, **after** the mutation and within the advisory lock:
- for the **actor:** "does the actor hold every permission this mutation hands out, at that scope?" (subset rule);
- for the **tenant:** "is there still ≥ 1 active owner?";
- in addition: no mutation on your own membership, and no change to a role you hold yourself.

A violation aborts the transaction. Because this runs in the DB under the advisory lock, there is no path through UI, server action or direct SQL that bypasses it.

### Tests (supplement AC4/AC7), all as direct SQL under `ios_app` unless stated
- D1: `set_config('app.membership_id'/'app.tenant_id'/'app.user_id'/'app.principal_type', <other>)` after `auth.begin` → identity unchanged; without `auth.begin` → 0 rows.
- D2: `INSERT/UPDATE` on `auth.tx_context` → permission denied.
- D3: `auth.begin` with a forged, revoked, expired or idle token, a token from another user, a tenant without membership, or a suspended membership → error, no context.
- D4: `auth.begin_job` from `ios_app` → refused; for a job of another tenant or an already-leased job → refused.
- D5: escalation via team (add self/another to a team with a stronger role), custom role (add a permission you don't have; change your own role), scoped assignment (scoped role with a tenant-wide permission), grant (self-grant) → refused, also via direct SQL.
- D6: **concurrency** with two real connections:
  - (a) revocation commits during a long write transaction → the revocation waits; the next write is refused;
  - (b) two admins demote each other simultaneously → one fails, ≥ 1 owner remains;
  - (c) two simultaneous invitation acceptances → exactly one succeeds.
- D7: a team role change bumps the `authz_epoch` of all team members (assert).
- D8: performance: 10k securables / 1M child rows, p95 overhead of `auth.begin` + policies reported (no pass/fail gate in M1, reported to the owner).

---

## C3. Immediate revocation

### Single source of truth
**PostgreSQL**: `sessions`, `users.status`, `tenant_memberships.status`, `tenants.status`, role, team and grant tables. There is no second store (no Redis, no JWT session, no IdP session as authority).

### Validation point
`auth.begin` in **every** transaction (C2). Session, user, tenant and membership validation happens in the **same transaction** as the data access, so there is no gap between "check" and "use".

| Event | Effect | Bound |
|---|---|---|
| Logout / admin revocation / "sign out everywhere" | `sessions.revoked_at` set | Next transaction refused. A running transaction finishes (≤ `statement_timeout` = 15 s) |
| Membership suspended | `status` + `authz_epoch` | Next transaction in that tenant refused; running **write** transactions finish first (lock); other tenants unaffected |
| User disabled | User status + epoch on all memberships + all sessions revoked | As above, all tenants |
| Role, team or grant withdrawn | `authz_epoch` of affected memberships | Next transaction computes the new rights; write ordering via the lock |
| Tenant suspended | `tenants.status` | Next transaction refused for everyone |
| SSO binding changed / policy drift | Sessions for that tenant revoked | Next transaction refused |

### Caching
- **DB:** no permission cache; computed per statement.
- **App:** `PrincipalAccess` exists only within one request transaction.
- **Next.js server:** tenant data is never stored in a shared cache (`use cache`, `unstable_cache` and `fetch` caching are banned for tenant data by an ESLint rule). Tenant pages are `force-dynamic` with `Cache-Control: no-store`.
- **Next.js client router cache:** `staleTimes.dynamic = 0`, so the browser doesn't show cached RSC payloads after revocation.
- **Browser/proxies:** `no-store` on all authenticated responses.

### Per channel
| Channel | Behaviour after revocation |
|---|---|
| Page (server component) | Next request: `auth.begin` fails → redirect `/login` (session) or 404 (membership/tenant) |
| API route | 401 (session) / 404 (tenant/membership) |
| Server action | Same guard (`guardedAction`) → refused, no state change |
| Tenant switch | Switching = `auth.begin` for the new tenant: membership in that tenant must be active; on success the session rotates (new token, old one revoked) |
| Background job | `auth.begin_job` re-validates the original member at **execution**: membership active, permission present, tenant active. Otherwise the job is refused + audited (`job.refused`) |
| Long-lived connections (SSE/WebSocket) | **Not in M1.** If added later: re-validate at least every 60 s and on every action |
| Idle tracking | `last_seen_at` is updated at most once per 60 s to avoid a write on every request. The idle bound is therefore precise to ±60 s |

### Tests (supplement AC5)
- R1: for each event in the table: next page / API / server action / tenant switch / job → refused, with the expected status code.
- R2: a running write transaction during suspension → the suspension waits, then the next write is refused (two connections).
- R3: the client router cache does not show stale tenant data after revocation (E2E: navigate back after suspension).
- R4: a job enqueued by a member who is suspended before execution → refused + audited.
- R5: a token rotated by a tenant switch → the old token is invalid immediately.
