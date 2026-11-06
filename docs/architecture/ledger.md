# Transactions and holdings model

Status: **proposed, awaiting approval**. It is built in the finance milestones, not in M0/M1. It is documented now because the A3 approval depends on it.

## Principles

1. **The ledger is the only source of truth. Holdings are derived.** Nobody, including admins, migrations and support staff, edits a holding directly.
2. **Append-only.** A posted transaction is never changed or deleted. The database enforces this with a trigger and no UPDATE/DELETE grants, the same as `audit_events`.
3. **Double entry per instrument.** Every transaction is balanced. For each instrument, the sum of `quantity` over the lines is 0. For each currency, the sum of `amount` over the cash lines is 0. This is enforced by a deferred constraint trigger at COMMIT.
4. **Corrections only through reversal plus new posting.** A correction is never an edit.
5. **Bitemporal.** `effective_date` is the economic date. `recorded_at` is when the system learned it. Reports can answer both "what was the position on 31-12?" and "what did we report on 15-01 about 31-12?".
6. **Four-eyes for posting.** Statuses go `draft` → `pending_approval` → `posted`. The approver cannot be the same person as the maker (M2 approval primitive).

## Accounts

A ledger account is `(ledger, party_id, instrument_id | currency)`.

- **Units ledger:** a holder party's position in an instrument. The issuer has an **issuance account** for each instrument whose balance is minus the outstanding amount. That makes the following always true:
  `Σ holdings(instrument) = −issuer_issuance_account(instrument)`, i.e. the register reconciles with what was issued.
- **Cash ledger** (commitments, calls, distributions, interest, fees): amounts per currency, with counter-accounts per fund or vehicle. Undrawn commitment is a balance, not a field.

## Example transactions

| Event | Units lines | Cash lines |
|---|---|---|
| Issuance of 1,000 shares to holding company X on settlement of a subscription | X: +1,000; issuer issuance account: −1,000 | X → vehicle: purchase price |
| Transfer of 200 from X to Y | X: −200; Y: +200 | (optional settlement) |
| Redemption of 100 from Y | Y: −100; issuance account: +100 | vehicle → Y: redemption amount |
| Capital call 25% | — | commitment drawdown per investor |
| Distribution | — | vehicle → holders, split by type (return of capital, income, gain) |

## Corrections and reversals

```
T1  posted  2026-03-01  X +1000 / issuer −1000        (wrong: should have been 900)
T2  posted  reverses T1   X −1000 / issuer +1000      (recorded_at = now, effective_date = T1.effective_date)
T3  posted  corrects T1   X +900  / issuer −900       (effective_date = 2026-03-01)
```

- `reverses_id` and `corrects_id` make the chain traceable. A transaction can be reversed only once, enforced by a unique constraint.
- **Period lock:** once a period has been reported (`ledger_period_locks`), backdating into it is refused. The correction is then booked in the open period with a reference to the original (`corrects_id`), and reports show it as a prior-period adjustment. Locking and unlocking a period requires four-eyes and is audited.

## Holdings projection

- `holdings_current (tenant_id, party_id, instrument_id, quantity, last_transaction_id)` is maintained **in the same transaction** as the posting, by the posting service. It is not maintained by triggers that something else could bypass.
- `holdings_as_of(date)` is a query over `ledger_entries` filtered by `effective_date ≤ date`, optionally `recorded_at ≤ t` for "as known at".
- **Nightly integrity check:** for every account, `holdings_current = Σ entries`, and the issuer's issuance account matches the sum of holdings. A difference is an incident, not a warning.

## Reconciliation against external sources

External sources include the share register or notary, transfer agent, fund administrator, bank statements and custodian.

1. **Import:** external positions or statement lines go into `recon_statements` and `recon_lines`, read-only and with the source document stored.
2. **Match:** rules plus manual matching produce `recon_matches`.
3. **Break:** whatever is left unmatched becomes a `recon_breaks` record with a status (`open` → `investigating` → `resolved_by_correction` | `resolved_external_error` | `accepted`), an owner and a deadline.
4. **Resolve:** a break is only ever resolved by a ledger correction (reversal plus posting, four-eyes) or by an explicit, justified acceptance. Never by editing data.

## Precision and currency

- Units are `numeric(28,10)` and `unit_scale` per instrument sets display rounding. Amounts are `numeric(20,4)` plus an ISO 4217 code. No floats anywhere.
- The ledger does no FX conversion. Conversion happens in reporting, with explicit, stored rates (`fx_rates` with source and date).

## Access control

Ledger lines carry the instrument's `securable_id`, which belongs to the project, fund or offering. A restricted project therefore also hides its transactions and holdings in the database, including aggregates. See [../security/rls-design.md](../security/rls-design.md).
