# Transfer of information is protected by transfer rules and agreements

`ISO27001-A.5.14-information-transfer` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.14 requires rules, procedures, and agreements to protect information in transit across all transfer types. Concord verifies a cosigned attestation of the transfer rules, the transfer agreements, and the protection mechanisms (e.g. encryption) applied.

## Why it matters

Information transfer (email, media, APIs, third parties) is a leading exfiltration and interception vector.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no information_transfer attestation collected
- attestation kind is <value>, expected "information_transfer"
- information_transfer attestation missing required field: <value>
- information_transfer review is overdue (next_review_due=<value>)
- information_transfer review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.14-information-transfer
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.14"
  nist_800_53:
  - "AC-4"
  - "SC-8"
```
