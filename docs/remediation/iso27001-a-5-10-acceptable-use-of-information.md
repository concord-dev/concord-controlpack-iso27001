# Acceptable use rules for information and assets are defined

`ISO27001-A.5.10-acceptable-use-of-information` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.10 requires rules for acceptable use of information and associated assets. Concord verifies a cosigned attestation of the acceptable-use rules, prohibited activities, and how user acknowledgement is tracked.

## Why it matters

A documented, acknowledged AUP is what makes disciplinary action for misuse enforceable and defensible.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no acceptable_use attestation collected
- attestation kind is <value>, expected "acceptable_use"
- acceptable_use attestation missing required field: <value>
- acceptable_use review is overdue (next_review_due=<value>)
- acceptable_use review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.10-acceptable-use-of-information
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.10"
  nist_800_53:
  - "PL-4"
  - "AC-20"
```
