# Zitadel EU test instance: setup for WP0

Purpose: a **test** instance with **synthetic users only**, used to record Zitadel's real token behaviour (evidence matrix, C1) and to read org login policies (V7, V8, V15–V18).
- No customer data.
- No production use.
- Not a contract decision.

Status: WP0 is **not yet authorised**. You can prepare the instance now; I'll only use it once you approve WP0.

> **Credentials rule:** never paste passwords, PATs, keys, client secrets or TOTP seeds into chat, tickets, commits or files in the repository. See §7 for how credentials reach the session.

Console labels change between Zitadel versions. Where a label below doesn't match exactly, pick the equivalent and note it, because that is useful evidence too.

## 1. Create the instance
1. Sign in to the Zitadel Cloud customer portal and create a new instance.
2. **Region: EU.** Record the exact region shown; it is evidence for V2.
3. Name: `investoros-test`. The free/development tier is enough.
4. Record (not secret): the instance domain (`https://<name>-xxxx.zitadel.cloud`) and the Zitadel version (shown in the console or `/debug/version` if available). You may share the domain and version in chat.

## 2. Instance default settings (Settings → Login behaviour and security)
| Setting | Value | Why |
|---|---|---|
| User registration (self sign-up) | **Off** | Staff-only; accounts are created by admins |
| Username/password login | On | Needed for the password-based matrix rows |
| External IdP login | On (only in the federated test org, see §3) | V7 / V17 |
| Second factors | TOTP **on**, U2F/WebAuthn **on**; SMS and e-mail OTP **off** | C1: SMS is not accepted |
| Passwordless (passkeys) | On | Matrix row "passkey" |
| **Force MFA** | **On** | D3 |
| **Force MFA for local authenticated users only** | **Off** | Federated users must also do Zitadel MFA (D3) |
| Login UI version | Record which one is active (V1 or V2) | Zitadel documents that **Hosted Login V2 does not support "Force MFA" for externally authenticated users** ([source](https://zitadel.com/docs/guides/integrate/login/hosted-login)). Federated tests (V7) must therefore run on the version that enforces it; see V18 |

## 3. Organisations (synthetic)
| Org | Login methods | Purpose |
|---|---|---|
| `synth-alpha` | Local accounts only (external IdP off) | Matrix rows: password, password+TOTP, password+U2F, passkey |
| `synth-beta` | External IdP on: a **second** Zitadel test instance (or another synthetic test IdP) configured as a generic OIDC IdP | V7 / V17: federated login with and without Zitadel MFA |

The organisation's ID is shown in its details; record it (not secret).

## 4. Project and application
1. Project `InvestorOS (test)` in `synth-alpha`. Grant the project to `synth-beta` (project grant) so its users can log in.
2. Application:
   - type **Web**;
   - authentication method **PKCE** (public client, **no client secret**).

   For WP0 this avoids a secret in the session. Production gets a confidential client, with its secret in AWS Secrets Manager; that is a WP4 decision.
3. Redirect URI `http://127.0.0.1:3000/auth/callback`; post-logout URI `http://127.0.0.1:3000/login`.
4. **Development mode: on.** It is required for `http://` loopback redirects; Zitadel's docs say to switch it off for production.
5. Token settings: leave "User info inside ID token" and "role assertion" **off**. We only need standard claims; `amr` is part of the ID token according to [Zitadel's claims documentation](https://zitadel.com/docs/apis/openidoauth/claims).
6. Record (not secret): the client ID.

## 5. Synthetic test users
Create these in `synth-alpha`, plus 1–2 in the federated IdP for `synth-beta`:

| User | Login method to set up |
|---|---|
| `wp0-password-only` | Password, **no** second factor (expected: refused) |
| `wp0-password-totp` | Password + TOTP |
| `wp0-password-u2f` | Password + security key (WebAuthn/U2F) |
| `wp0-passkey` | Passkey only (passwordless) |

- Use fictional names and e-mail addresses on the reserved domain `example.invalid`; mark them verified in the console.
- **Passwords, TOTP seeds and security keys stay with you.** You'll perform the test logins yourself during WP0, through a claims-recording page that stores only the **ID-token claims** (no tokens, no secrets) as test fixtures. I'll deliver that page in WP0.

## 6. Service account (minimum permissions)
1. Users → **Service accounts** → new: `investoros-wp0-reader` (in `synth-alpha`).
2. Authentication: **Personal Access Token (PAT)** with a **short expiry (≤ 30 days)**.
   - Why a PAT and not the private-key JWT Zitadel normally recommends: a PAT can be injected by this environment's network proxy (§7), so the secret never enters the container, logs or chat. A private key would have to be stored inside the container.
   - The PAT's weakness is its long lifetime; that is mitigated by the short expiry, read-only rights and test instance only.
   - For production (drift check), the decision is private-key JWT in AWS Secrets Manager.
3. Administrator roles: **only `ORG_OWNER_VIEWER`**, granted **separately on `synth-alpha` and `synth-beta`**. That is read-only access to the org including its login policy (Zitadel role table: [Administrators](https://zitadel.com/docs/guides/manage/console/administrators)).

| Grant | WP0 | Note |
|---|---|---|
| `ORG_OWNER_VIEWER` on each test org | **required** | Read login policy (`GetLoginPolicy`), org ID, IdP configuration |
| `IAM_OWNER_VIEWER` (instance-wide) | **not** | Wider than needed (sees all orgs) |
| `ORG_USER_MANAGER`, `ORG_OWNER`, `IAM_OWNER` | **never** | Write rights; not needed. Test users are created by you in the console |
| Project roles / user grants | not needed | — |

Record (not secret): the service account's user ID.

## 7. Handing over credentials
- **Never** in chat, commits, tickets or files.
- When WP0 is authorised, I'll open the environment's **secure credential form** for the host `<your-instance>.zitadel.cloud` (header `Authorization: Bearer`). You enter the PAT there.
- The network proxy adds the header to requests to that host only. I never see the value, it doesn't enter the container, and it doesn't appear in logs.
- If the form is unavailable in your app, add the credential yourself under the environment's network secrets with the same host.
- Revoke the PAT in the Zitadel console as soon as WP0 is finished.

## 8. What you can share in chat (not secret)
Instance domain, region, Zitadel version, login UI version, org IDs, project ID, client ID, service-account user ID, and which settings in §2 matched or differed.
