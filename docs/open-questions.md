# Open questions for the owner

| # | Question | Why it matters | Proposal |
|---|---|---|---|
| Q1 | Do we add the party kind `arrangement` (FGR, CV, contractual fund, compartment)? | Without it, entities without legal personality are recorded as legal entities, which is legally wrong | Yes |
| Q2 | Participation as a derived projection (no editable table)? | Avoids a third source of truth beside the ledger | Yes; historical imports in a separate non-authoritative table |
| Q3 | Should owners/admins see restricted projects **only** through an explicit grant? (implemented that way now) | Strict barrier vs. convenience | Yes; compliance has read-only oversight |
| Q4 | Four-eyes on restricted grants from M2: who may approve? | Closes the self-grant gap | Another holder of `access.manage`, or compliance |
| Q5 | Which locales besides EN/NL in M1 (DE/FR)? | Translation effort | DE in M1, FR on demand |
| Q6 | Session lifetime: idle 30 min / absolute 12 h acceptable? | Security vs. usability | Yes; per tenant configurable later |
| Q7 | Repository name `InvesterOS` (typo of Investor)? | Cosmetic, but appears in URLs and integrations | Rename now, while it's cheap |
