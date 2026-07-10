# Conflicting duties are segregated to reduce fraud and error

`ISO27001-A.5.3-segregation-of-duties` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.3 requires conflicting duties and areas of responsibility to be segregated. Concord verifies a cosigned attestation documenting the conflicting-duties matrix, the separation controls enforcing it, and the periodic review process.

## Why it matters

Without segregation of duties a single actor can both commit and conceal fraud; SoD is a core preventive control auditors probe directly.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no segregation_of_duties attestation collected
- attestation kind is <value>, expected "segregation_of_duties"
- segregation_of_duties attestation missing required field: <value>
- segregation_of_duties review is overdue (next_review_due=<value>)
- segregation_of_duties review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.3-segregation-of-duties
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.3"
  nist_800_53:
  - "AC-5"
```
