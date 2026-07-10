# Information security requirements are agreed with each supplier

`ISO27001-A.5.20-information-security-in-supplier-agreements` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.20 requires relevant information security requirements to be established and agreed with each supplier. Concord verifies a cosigned attestation of the security clauses, the coverage across the supplier base, and the review process.

## Why it matters

Third parties are a top breach vector; contractual security requirements are the enforceable baseline for supplier risk.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no supplier_agreements attestation collected
- attestation kind is <value>, expected "supplier_agreements"
- supplier_agreements attestation missing required field: <value>
- supplier_agreements review is overdue (next_review_due=<value>)
- supplier_agreements review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.20-information-security-in-supplier-agreements
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.20"
  nist_800_53:
  - "SR-2"
  - "SA-4"
```
