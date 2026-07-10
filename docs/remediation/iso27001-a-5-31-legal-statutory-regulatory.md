# Legal, statutory, and regulatory requirements are identified and met

`ISO27001-A.5.31-legal-statutory-regulatory` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.31 requires legal, statutory, regulatory, and contractual requirements to be identified, documented, and kept current. Concord verifies a cosigned attestation of the applicable requirements, the identification process, and compliance tracking.

## Why it matters

Undiscovered legal/regulatory obligations are a direct source of fines and are a mandatory A.5.31 audit line.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no legal_requirements attestation collected
- attestation kind is <value>, expected "legal_requirements"
- legal_requirements attestation missing required field: <value>
- legal_requirements review is overdue (next_review_due=<value>)
- legal_requirements review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.31-legal-statutory-regulatory
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.31"
  nist_800_53:
  - "PM-1"
```
