# Confidentiality / NDA agreements are signed where required

`ISO27001-A.6.6-confidentiality-or-non-disclosure-agreements` · framework **iso27001** · severity **medium** · People Controls

## What this control checks

ISO/IEC 27001:2022 A.6.6 requires confidentiality or non-disclosure agreements reflecting the organization's information protection needs. Concord verifies a cosigned attestation of the NDA requirements, coverage across personnel and third parties, and the review process.

## Why it matters

NDAs are the contractual backstop for confidential information shared with staff and partners.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no nda_management attestation collected
- attestation kind is <value>, expected "nda_management"
- nda_management attestation missing required field: <value>
- nda_management review is overdue (next_review_due=<value>)
- nda_management review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.6.6-confidentiality-or-non-disclosure-agreements
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.6.6"
  nist_800_53:
  - "PS-6"
```
