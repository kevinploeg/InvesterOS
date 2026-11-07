# M1 stage 1 report: WP1, WP2, WP3, WP9

Date: 2026-11-07 · Branch `m0-foundations` · Synthetic data only · Not deployed
Baseline before this stage: M0 green at `bff1253` (CI run 42300191852).
WP4–WP10 have **not** been started.

## 1. Pre-WP1 safety verification of `auth.tx_context`

The approved design stored the context in a shared table keyed by `(backend pid, transaction start time)`. **I rejected that before building.** Wall-clock time is not monotonic and backend pids are reused, so a committed row could in principle match a later transaction and hand it another user's identity.

**Implemented instead:** a temp table per connection, owned by `ios_definer`, with `ON COMMIT DELETE ROWS`. Request roles have no TEMPORARY privilege. Each property was verified with a prototype first and then with tests:

| Property | Result | Test |
|---|---|---|
| COMMIT / ROLLBACK clear the context | ✅ | `context-safety.test.ts` |
| Backend reuse by another user (pool of 1, same pid) | ✅ no leakage | idem |
| 200 interleaved transactions over 8 backends | ✅ 0 crossed identities | idem |
| Second `auth.begin` in the same transaction | ✅ refused (`IOS09`) | idem |
| Savepoint rollback | ✅ context gone (fail closed) | idem |
| `DISCARD TEMP` mid-transaction / `DISCARD ALL` (pooler reset) | ✅ fail closed / clean backend | idem |
| Autocommit | ✅ context lasts exactly one statement | idem |
| `ios_app` SELECT/INSERT/UPDATE/DELETE/TRUNCATE/ALTER on the store | ✅ refused | idem |
| `ios_app` CREATE TEMP TABLE / pg_temp function (shadowing) | ✅ refused | idem |
| Two-phase commit with a context | ✅ refused by Postgres | idem |
| `set_config('app.*')` before/after `auth.begin` | ✅ no effect (readers ignore GUCs; schema-lint R9) | idem |

Not supported: PgBouncer **statement** mode. Transaction and session mode are fine.

## 2. What was built

| WP | Content | Commit |
|---|---|---|
| WP1 | `auth.begin(token, tenant, mode)` validates session, user, tenant and membership in the DB; context store as above; `ios_auth` role (only it can create sessions); `ios_app` has no access to `sessions`; schema-lint R9 (no GUC identity), R10 (definer scope), R11 (no TEMP for request roles) | `5ceff53` |
| WP2 | `authz_epoch` + bump triggers; `write`/`iam` modes with `FOR SHARE` on membership and tenant; per-tenant IAM advisory lock taken before row locks; single permission evaluator; jobs primitive with re-validation at execution time; tenant switch = token rotation; role timeouts (statement 15 s, idle in transaction 30 s, lock 10 s) | `75839f8` |
| WP3 | DB triggers: iam mode required; no self-mutation (incl. **self-grant: the M0 gap is closed**); subset rule on granting **and** revoking (direct, team, custom, scoped); no demoting or suspending a stronger member; last-owner guard | `ac42f44` |
| WP9 | Actions pinned to SHAs (current majors, no more Node 20 warning in CI), Renovate config, ESLint ban on `use cache`/`unstable_cache`, `staleTimes` 0, E2E revocation test | `9f5e480` |
| Follow-up | Benchmark finding fixed: set-based visibility policy (see §4) | `ec47fcf` |

## 3. Security test results

| Suite | Tests | Covers |
|---|---|---|
| db `schema.test.ts` | 6 | Lint positive + negative, incl. R9/R10/R11 |
| `context-safety.test.ts` | 26 | §1 |
| `isolation.test.ts` | 14 | Generated per tenant table (incl. the new `jobs` table, picked up automatically); B cannot establish a context in A; `IOS04` identical for foreign and non-existent tenants |
| `restricted.test.ts` | 28 | Information barrier unchanged; self-grant refused in every mode |
| `revocation.test.ts` | 18 | D6a: role revocation, suspension and tenant suspension **wait** for in-flight writes, after which writes are refused; a write that starts after a revocation is refused at `auth.begin`; reads take no locks; IAM serialisation; D7 epoch bumps (team, role permissions, grants, user disable across all tenants); R4 jobs (runs as the enqueuer, refusal on suspension or withdrawn permission, no double execution, failure rolls back, no impersonated enqueue); R5 rotation |
| `iam.test.ts` | 16 | (a)–(d) above, incl. concurrent mutual demotion → ≥ 1 owner remains |
| `auth.test.ts` | 23 | OIDC unchanged; sessions now enforced in the DB; only `ios_auth` mints sessions |
| `authz.test.ts` | 162 | Matrix + DB parity (now via the definer evaluator) |
| `db-audit.test.ts` | 13 | Audit append-only; credential never serialised; system context only for `ios_worker` |
| E2E (Playwright) | 12 | M0 flows + tenant switch rotates the token (old cookie → 401) + suspension makes the tenant unreachable at once while the other tenant keeps working |
| **Total** | **318** | Kernel coverage 100/100/100/100 |

**M0 regression:** all M0 assertions still run. Where the mechanism changed, the assertion was made **stricter**, never looser:
- spoofing a malformed GUC → spoofing a membership that doesn't exist (`IOS04`);
- "app sees only its own sessions" → "app has no access to sessions at all";
- "suspended member sees 0 rows" → "suspended member gets no context at all";
- the "known gap" test → a test that the gap is closed.

## 4. Performance measurements (D8)

Local: PostgreSQL 16.15, 4 vCPU container, 1 connection, 2,000 iterations. **Indicative.** Production (RDS) will differ.

| Measurement | p50 | p95 | p99 |
|---|---|---|---|
| Baseline `BEGIN; SELECT 1; COMMIT` | 0.22 ms | 0.37 ms | 0.92 ms |
| `auth.begin` read + COMMIT | 1.58 ms | 2.35 ms | 3.65 ms |
| `auth.begin` write + COMMIT | 1.64 ms | 2.28 ms | 3.81 ms |
| `auth.begin` iam + COMMIT | 1.57 ms | 2.19 ms | 3.39 ms |
| read + point query under RLS | 1.78 ms | 2.62 ms | 3.93 ms |
| read + child rows of 1 securable (100 rows, 10k securables) | 7.09 ms | 9.76 ms | 10.90 ms |
| read + `count(*)` over 1M child rows (910k visible; correct) | 161 ms | 260 ms | — |

- **Overhead of the DB-verified context:** about 1.4 ms per transaction (p50). Acceptable for the MVP.
- **Finding fixed:** the original child-table policy (per-row function call) **exceeded the 15 s statement timeout** on 1M rows. With the set-based semi-join it takes 0.16 s, with identical semantics (all barrier tests green).
- **Open performance item for M3:** the semi-join builds a hash of all visible securable IDs per statement (≈ 5 ms at 10k). At much larger numbers, switch to a deny-list (only the non-granted restricted IDs) or a materialised visibility table. Measure again in M3.

## 5. Unresolved risks and limitations

| # | Risk | Severity | Status / proposal |
|---|---|---|---|
| 1 | A compromised **application server** sees tokens in transit and can act as every active user | High (inherent) | Not solvable in the DB; hosting hardening, short sessions, monitoring (M5) |
| 2 | **Two colluding access managers** can grant each other access to restricted resources (self-grant is blocked; mutual grants are not) | Medium | M2: four-eyes approval on restricted grants |
| 3 | `auth.begin` costs ≈ 1.4 ms per transaction; several transactions per page add up | Low | Measure on RDS in M5; if needed, one transaction per request |
| 4 | **Session revocation (logout) does not wait** for a running write transaction of the same session; membership/role/tenant revocations do | Low | Deliberate: the bound is ≤ 15 s (statement timeout). Can be tightened later if needed |
| 5 | Tenant switch via GET: a forged link can rotate a victim's **own** session to a tenant they already belong to | Low | No data change; documented. Can become POST when the switcher UI is built (WP7) |
| 6 | PgBouncer statement mode is not supported | Low | Hosting choice: transaction mode or RDS Proxy (validate in M5) |
| 7 | Migration 0005 was amended after its first commit (`v_ctx` record bug) | Low | Allowed because **nothing is persistently deployed**. From the first persistent environment onwards, migrations are immutable (checksum check) |
| 8 | GitHub Actions moved to new majors (checkout v7, setup-node v7, pnpm action v6, upload-artifact v7, gitleaks v3) | Low | CI is green on them; Renovate will propose further majors only with approval |
| 9 | **Zitadel Login V2 doesn't support "Force MFA" for federated users** (V18) | **Medium-high for WP5** | Confirm in WP0; otherwise Login V1 or federated SSO later |
| 10 | Renovate only works once the Renovate GitHub App is installed | Low | Owner action |
| 11 | Local tests ran on PG 16, CI on PG 17 | Low | Both green |

## 6. CI evidence
Every commit in this stage is green in GitHub Actions (verify + secret scan). See the run list on the branch.
