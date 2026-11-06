# Zitadel vendor verification (rev. 1)

Date: 2026-11-06 · Method: desk research on Zitadel's public documentation. Contract documents, the Trust Center (behind NDA) and statements from Zitadel itself have **not** been reviewed.

**Status per item:**
- ✅ Verified from a primary source (vendor documentation).
- ⚠️ Partly verified, or sources conflict.
- ❌ Not publicly available; needs written confirmation from Zitadel.

## Correction to my earlier advice

In ADR-0004 and in chat I described Zitadel as a **Swiss** company under the EU adequacy decision for Switzerland. That is incomplete. Zitadel's own corporate-structure page says:
- **ZITADEL Inc. (US) is the parent company** and **CAOS AG (Switzerland) is the operating subsidiary**.
- Cloud customers normally contract with CAOS AG under Swiss law.

([source](https://help.zitadel.com/corporate-structure-contracting-entities))

A US parent means US-law exposure (CLOUD Act) cannot be ruled out on the basis of the Swiss contracting entity alone. That puts Zitadel in roughly the same risk category as AWS. It does not change the recommendation (the exit strategy remains the deciding advantage), but the argument must be stated correctly.

## Findings

| # | Item | Finding | Status | Source |
|---|---|---|---|---|
| V1 | Certifications | ISO/IEC 27001:2022 and SOC 2 Type II, according to the vendor. Reports are available through the Trust Center | ⚠️ self-reported; reports not reviewed | [certifications](https://help.zitadel.com/security-compliance/certifications-and-compliance), [SOC 2 blog](https://www.zitadel.com/blog/zitadel-achieves-soc2-type-ii-certification) |
| V2 | Data residency | Regions US, EU, CH, AU selectable; user data stored in the chosen region | ✅ | [data location](https://help.zitadel.com/where-is-zitadel-cloud-data-stored), [Zitadel Cloud](https://zitadel.com/zitadel-cloud) |
| V3 | **Processing outside the EU** | The DPA/GDPR page says customer data **may be processed outside Switzerland/EU, including the US**, through subprocessors. "EU region" therefore means **storage**, not "no transfers" | ⚠️ material: extent unknown | [GDPR](https://zitadel.com/gdpr), [DPA](https://zitadel.com/docs/legal/data-processing-agreement) |
| V4 | Transfer basis | EU-US DPF self-certification (+ UK extension, Swiss-US DPF), SCCs for other transfers. Legal risk: the DPF was upheld by the EU General Court (Latombe, Sept 2025), but an appeal is pending | ✅ basis / ⚠️ legal risk | [GDPR](https://zitadel.com/gdpr) |
| V5 | Subprocessors | The current list is only in the Trust Center (with change notifications). Older docs list Google LLC (cloud infrastructure, CDN, DDoS) | ❌ full list not seen | [subprocessors (docs)](https://zitadel.com/docs/legal/subprocessors), [Trust Center](https://trust.zitadel.com/subprocessors) |
| V6 | **Support access** to customer data | No public policy found on who can access tenant data, from where, or with what approval and logging | ❌ | — |
| V7 | **MFA claims** | `amr` appears **in the ID token** (not in access token, userinfo or introspection), values per RFC 8176 (`pwd`, `mfa`, `otp`, …). Behaviour with **federated login** (whether Zitadel MFA after an external IdP produces `amr: mfa`) is not documented | ✅ local / ❌ federated | [claims](https://zitadel.com/docs/apis/openidoauth/claims) |
| V8 | Org claim for tenant mapping | Resource-owner/org claims exist through Zitadel's reserved scopes; exact claim and scope behaviour must be tested on our version | ⚠️ test in staging | [scopes](https://zitadel.com/docs/apis/openidoauth/scopes) |
| V9 | SLA | Service level description: 99.50% monthly default, 99.95% extended; credits are the **only** remedy, requested within 30 days. Marketing pages list other percentages (Pro 99.5%, Enterprise "up to 99.99%"); sources conflict | ⚠️ contract is decisive | [SLD](https://zitadel.com/docs/legal/service-description/service-level-description), [pricing](https://zitadel.com/pricing) |
| V10 | Licence / exit strategy | Since v3 (2025) the core is **AGPL-3.0**; APIs/SDKs Apache-2.0. Using it unmodified (self-hosted) is allowed; modifications offered as a service must be published under AGPL. A commercial licence is available. Not retroactive | ✅ | [AGPL blog](https://zitadel.com/blog/apache-to-agpl), [licence FAQ](https://zitadel.com/license-faq) |
| V11 | **Data export on exit** | Not verified: can users, orgs, identity links and MFA factors (or at least password hashes) be exported? Re-enrolling MFA for all users would be a significant migration cost | ❌ | — |
| V12 | **DORA Art. 30 contract terms** | Customised terms (MSA/DPA) are, according to the vendor, only for Enterprise (custom pricing, minimum annual contract value). Audit rights, incident notification times, exit assistance and subcontracting terms are not publicly confirmed | ❌ material | [Pro vs Enterprise](https://help.zitadel.com/zitadel-cloud-pro-vs.-enterprise-which-plan-is-right-for-you), [enterprise pricing](https://help.zitadel.com/zitadel-enterprise-pricing-metrics) |
| V13 | Price | Pro from $100/month (25k DAU); Enterprise custom | ✅ (indicative) | [pricing](https://zitadel.com/pricing) |
| V14 | Incident notification time | Not found publicly (needed under GDPR Art. 33 and as DORA input) | ❌ | — |

## Conclusion

1. **Technically suitable.** The organisation model, OIDC/SAML, `amr` in the ID token and the self-hosting exit route fit M1.
2. **Contractually not yet.** V6, V11, V12 and V14 are blocking for a DORA-supervised customer base. Realistically, **Enterprise** is needed to get DORA-compliant terms. That is a cost decision you should take before go-live, not before M1.
3. **Implications for M1:**
   - **Development can start against a Zitadel test instance** (synthetic users only, no customer data). That is the only way to test V7 (federated MFA) and V8 (org claim) properly.
   - No production contract until V5, V6, V11, V12 and V14 are answered in writing.
4. **Fallback if Zitadel won't offer DORA terms:** self-host Zitadel (AGPL, unmodified) on our own AWS account in Frankfurt.
   - It removes the subprocessor and support-access risks.
   - In exchange, we take on operations: patching, availability, and MFA/SMS delivery.
   - The application code doesn't change, thanks to plain OIDC.

## Questions to send to Zitadel (in writing)

1. The current subprocessor list, with processing location and purpose for each, for an EU-region tenant (incl. e-mail/SMS, support tooling, logging/monitoring).
2. Support access policy: who can access EU-tenant data, from which countries, with what approval, logging and customer notification.
3. Which data leaves the EU in normal operation (telemetry, logs, backups, support)?
4. Can the Enterprise contract include DORA Art. 30 terms: audit and access rights, incident notification time, exit assistance and transition period, subcontracting conditions, location of processing?
5. Data export: format and completeness (users, orgs, identity links, password hashes, MFA factors).
6. Federated login: does Zitadel produce `amr` containing `mfa` when it enforces MFA after an external IdP? Can MFA be enforced for federated users?
7. Incident notification time to customers in the SLA/DPA.
8. Do the US parent company (ZITADEL Inc.) or its staff have access to EU-tenant data?
