# Privacy and protection of PII is ensured per regulations

`ISO27001-A.5.34-privacy-and-pii` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.34 requires identifying and meeting requirements for privacy and protection of PII. Concord verifies a cosigned attestation of the PII inventory, the legal basis for processing, and the data-subject-rights process.

## Why it matters

PII mishandling triggers GDPR/CCPA penalties and breach notification; A.5.34 is the privacy anchor control.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no privacy_pii attestation collected
- attestation kind is <value>, expected "privacy_pii"
- privacy_pii attestation missing required field: <value>
- privacy_pii review is overdue (next_review_due=<value>)
- privacy_pii review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.34-privacy-and-pii
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.34"
  nist_800_53:
  - "PT-1"
  - "PT-3"
```
