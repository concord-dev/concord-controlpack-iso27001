# Information labelling is consistent with the classification scheme

`ISO27001-A.5.13-labelling-of-information` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.13 requires an appropriate set of procedures for information labelling. Concord verifies a cosigned attestation of the labelling procedure, the label types in use, and the tooling that applies them.

## Why it matters

Labels are how classification is actually enforced by people and DLP tooling at the point of handling.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no information_labelling attestation collected
- attestation kind is <value>, expected "information_labelling"
- information_labelling attestation missing required field: <value>
- information_labelling review is overdue (next_review_due=<value>)
- information_labelling review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.13-labelling-of-information
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.13"
  nist_800_53:
  - "MP-3"
```
