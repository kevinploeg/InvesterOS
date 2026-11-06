# Domain model (revision 2)

Status: **proposed, awaiting approval**. None of these tables exist yet. They are built from M3 onwards. M0/M1 build only the kernel: identity, access, securables and audit.

This revision covers the approval feedback:

- **A1–A4:** natural persons, legal entities, commercial investor relationships and legal holdings are separate concepts. Holdings are derived from an auditable ledger (see [ledger.md](ledger.md)).
- **A5 (rejected in its old form):** commercial **opportunities (deals)** are now separate from formal **offerings** and the **subscription** process.
- **A6:** a fund is a logical structure with one or more vehicles. It is not mapped one-to-one onto a legal entity, and contractual funds without legal personality are supported.
- **A7:** every sensitive object hangs off a **securable**, which enforces access in the database. See [../security/rls-design.md](../security/rls-design.md).

## Concepts

| Concept | What it is | What it is not |
|---|---|---|
| **Party** | A legal or natural person, or a contractual arrangement, that can hold rights or obligations. `kind`: `person`, `organization`, `arrangement`. | A commercial relationship or a login. |
| **Person** | A natural person (a subtype of party). Can be a contact, representative, director, signatory, UBO or direct holder. | An "investor" by default. |
| **Legal entity** | An organization with legal personality (BV, NV, GmbH, S.à r.l., LP with personality, …), as a party subtype. | A fund by default. |
| **Arrangement** | A party without legal personality: a Dutch FGR, CV, a contractual fund or a compartment without legal personality. Its legal title usually sits with a custodian or title holder, which is recorded as a relationship. | A legal entity. |
| **Investor (relationship)** | The commercial relationship the firm manages: coverage owner, segment, status, CRM history. It groups 1..n holder parties, e.g. a family with three holding companies and one direct holding. | A legal owner. It never holds anything itself. |
| **Contact** | A person linked to an investor relationship in a role (decision maker, advisor, back office). | A holder. |
| **Project** | An economic asset or operating business: a building, a vessel, a wind farm, a loan book, an operating company. It can have sub-projects (a portfolio). | A fund, SPV or deal. |
| **Fund** | A logical fund structure with vehicles (main fund, parallel, feeder, AIV, co-invest, GP, blocker), optionally umbrellas and compartments. | One legal entity. |
| **Instrument** | A right issued by a party: shares, fund units, LP interest, note, bond, loan, profit participation. It optionally has an economic link to a project or fund. | A holding. |
| **Opportunity (deal)** | A commercial pipeline item: sourcing → screening → DD → IC → structuring → won/lost. It carries soft, non-binding investor interest. | A legal offer. |
| **Offering** | A formal offer of one or more instruments by an issuer, with terms, documents, eligibility, a window and one or more closings. | A pipeline item or a CRM record. |
| **Subscription** | A binding application by a holder party, on behalf of an investor relationship, for an instrument in an offering. It has a lifecycle and needs four-eyes acceptance. | A holding. Once settled it produces ledger transactions. |
| **Participation** | A **derived read model**: the economic exposure of an investor relationship to a project or fund, computed from holdings × instrument links (optionally with look-through). | A table anyone writes to. |
| **Transaction / ledger** | Append-only, balanced position and cash movements. The source of truth. | Editable. |
| **Holding** | A projection: a party's quantity of an instrument at a date, computed from the ledger. | Editable. |

## ERD

```mermaid
erDiagram
  parties ||--o| persons : "kind=person"
  parties ||--o| legal_entities : "kind=organization"
  parties ||--o| arrangements : "kind=arrangement"
  parties ||--o{ party_relationships : "from"
  parties ||--o{ party_relationships : "to"

  investors ||--o{ investor_holders : "groups"
  parties ||--o{ investor_holders : "holder"
  investors ||--o{ investor_contacts : "has"
  persons ||--o{ investor_contacts : "is"

  funds ||--o{ fund_vehicles : "consists of"
  parties ||--o{ fund_vehicles : "vehicle (entity or arrangement)"
  funds ||--o{ funds : "umbrella / compartment"

  projects ||--o{ projects : "portfolio"
  projects ||--o{ project_parties : "structured via"
  parties ||--o{ project_parties : "owner_spv / opco / borrower / lender / manager"

  parties ||--o{ instruments : "issues"
  projects ||--o{ instruments : "economic link (opt)"
  funds ||--o{ instruments : "economic link (opt)"

  opportunities ||--o{ opportunity_projects : "concerns"
  projects ||--o{ opportunity_projects : ""
  opportunities ||--o{ opportunity_interests : "soft interest"
  investors ||--o{ opportunity_interests : ""
  opportunities |o--o{ offerings : "may lead to"

  parties ||--o{ offerings : "issuer"
  offerings ||--o{ offering_instruments : "offers"
  instruments ||--o{ offering_instruments : ""
  offerings ||--o{ offering_closings : "closes in"
  offerings ||--o{ subscriptions : "receives"
  investors ||--o{ subscriptions : "on behalf of"
  parties ||--o{ subscriptions : "legal subscriber"
  instruments ||--o{ subscriptions : "for"
  offering_closings |o--o{ subscriptions : "admitted at"
  subscriptions ||--o{ subscription_events : "history"

  ledger_transactions ||--|{ ledger_entries : "balanced lines"
  ledger_transactions |o--o| ledger_transactions : "reverses / corrects"
  subscriptions |o--o{ ledger_transactions : "settles into"
  instruments ||--o{ ledger_entries : "unit account"
  parties ||--o{ ledger_entries : "account holder"
  ledger_entries }o--|| holdings_current : "projects into"

  securables ||--o| projects : "governs"
  securables ||--o| funds : "governs"
  securables ||--o| opportunities : "governs"
  securables ||--o| offerings : "governs"

  parties { uuid id PK; text kind "person|organization|arrangement"; text display_name; text status }
  persons { uuid party_id PK; text given_name; text family_name; date birth_date; text nationality }
  legal_entities { uuid party_id PK; text legal_name; text entity_type; text jurisdiction; text registration_no; text lei }
  arrangements { uuid party_id PK; text arrangement_type "fgr|cv|contractual_fund|compartment"; uuid title_holder_party_id }
  party_relationships { uuid id PK; uuid from_party_id; uuid to_party_id; text type "representative|director|signatory|beneficial_owner|shareholder_of_record|custodian|title_holder|contact_of"; numeric ownership_pct; numeric control_pct; date valid_from; date valid_to; text evidence_ref }
  investors { uuid id PK; text display_name; text segment; text status; uuid coverage_membership_id }
  investor_holders { uuid investor_id; uuid party_id; text role "holding_vehicle|direct_holder|nominee" }
  investor_contacts { uuid investor_id; uuid person_party_id; text role }
  funds { uuid id PK; uuid securable_id; uuid parent_fund_id; text fund_type; text structure "standalone|umbrella|compartment"; uuid aifm_party_id; text base_currency; int vintage }
  fund_vehicles { uuid fund_id; uuid party_id; text role "main|parallel|feeder|aiv|co_invest|gp|blocker|master" }
  projects { uuid id PK; uuid securable_id; uuid parent_project_id; text asset_class "real_estate|shipping|infrastructure|private_credit|operating_company|other"; text status; text country; jsonb attributes; int attributes_schema_version }
  project_parties { uuid project_id; uuid party_id; text role; date valid_from; date valid_to }
  instruments { uuid id PK; uuid issuer_party_id; uuid project_id; uuid fund_id; text instrument_type; text currency; numeric nominal; int unit_scale; text isin; jsonb terms }
  opportunities { uuid id PK; uuid securable_id; text name; text stage "sourcing|screening|due_diligence|ic|structuring|won|lost"; numeric indicative_size; text currency; uuid lead_membership_id }
  opportunity_interests { uuid opportunity_id; uuid investor_id; text level "approached|interested|soft_circled|declined"; numeric indicative_amount; text currency }
  offerings { uuid id PK; uuid securable_id; uuid opportunity_id; uuid issuer_party_id; text offering_type "primary|follow_on|secondary|refinancing"; text status "draft|approved|open|closed|settled|cancelled"; numeric target_amount; numeric max_amount; text currency; jsonb eligibility; timestamptz opens_at; timestamptz closes_at }
  offering_instruments { uuid offering_id; uuid instrument_id; numeric price; numeric min_ticket }
  offering_closings { uuid id PK; uuid offering_id; int seq; date closing_date; text status }
  subscriptions { uuid id PK; uuid offering_id; uuid investor_id; uuid subscriber_party_id; uuid instrument_id; uuid closing_id; text status "draft|submitted|kyc_pending|accepted|allocated|funded|settled|rejected|withdrawn"; numeric requested_amount; numeric allocated_amount; text currency; uuid approval_request_id }
  subscription_events { uuid id PK; uuid subscription_id; text from_status; text to_status; uuid actor_membership_id; timestamptz at }
  ledger_transactions { uuid id PK; text type; text status "draft|pending_approval|posted"; date effective_date; timestamptz recorded_at; uuid reverses_id; uuid corrects_id; uuid subscription_id; uuid approval_request_id }
  ledger_entries { uuid id PK; uuid transaction_id; text ledger "units|cash"; uuid party_id; uuid instrument_id; text currency; numeric quantity; numeric amount }
  holdings_current { uuid party_id; uuid instrument_id; numeric quantity; date as_of "projection" }
  securables { uuid id PK; text kind; text classification "standard|restricted" }
```

Every table above also has `tenant_id`, a primary key of `(tenant_id, id)`, composite foreign keys and RLS, the same as the kernel tables.

## Design decisions to approve

1. **The party supertype now includes arrangements.** Dutch FGRs and CVs have no legal personality but do issue rights and appear in structures. Without this kind, they get forced into `legal_entities`, which is legally wrong and would surface in reporting.
2. **Participation is a projection, not a table.** It is derived from holdings × instrument links. That removes the third source of truth. If you need a manually maintained "participation" (for example historical data without a ledger), that would be a separate, explicitly non-authoritative import table.
3. **An opportunity can lead to 0..n offerings**, for example an equity tranche plus a mezzanine note. An offering can also exist without an opportunity, for example a follow-on raise.
4. **Soft interest (`opportunity_interests`) never becomes a subscription automatically.** A subscription is always a new, explicit, binding act with its own lifecycle and four-eyes acceptance.
5. **Asset-class-specific project fields** are stored as `attributes jsonb`, validated per asset class and `attributes_schema_version` by versioned Zod schemas. Fields the finance or reporting module filters or aggregates on are promoted to typed columns or extension tables. That avoids both a 200-column table and an unvalidated JSON dump.
6. **Ownership is recorded in two different ways, by design:**
   - Economic ownership of instruments the tenant administers is recorded in the **ledger**.
   - Structure, control and UBO information about external structures, such as the investor's own holding chain, is recorded in **party_relationships**, with evidence and validity dates.
   - The same economic interest must never be recorded both ways. A validation will enforce this in M3.
