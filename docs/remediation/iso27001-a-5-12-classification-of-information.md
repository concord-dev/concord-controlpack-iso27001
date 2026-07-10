# Information is classified according to legal, business, and security needs

`ISO27001-A.5.12-classification-of-information` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.12 requires information to be classified per confidentiality, integrity, availability, and legal requirements. Concord verifies a cosigned attestation of the classification scheme, the classification criteria, and the per-level handling rules.

## Why it matters

Classification drives every downstream protection decision; an absent or unapplied scheme collapses data-handling controls.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no information_classification attestation collected
- attestation kind is <value>, expected "information_classification"
- information_classification attestation missing required field: <value>
- information_classification review is overdue (next_review_due=<value>)
- information_classification review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.12-classification-of-information
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.12"
  nist_800_53:
  - "RA-2"
  - "MP-3"
```
