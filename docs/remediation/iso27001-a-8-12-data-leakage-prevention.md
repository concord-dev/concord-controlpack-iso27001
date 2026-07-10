# DLP controls are deployed on systems handling sensitive information

`ISO27001-A.8.12-data-leakage-prevention` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.12 requires data leakage prevention measures on systems, networks, and devices that process, store, or transmit sensitive information. Concord verifies a cosigned attestation of the DLP controls, the monitored channels, and coverage.

## Why it matters

DLP is the last-line detective/preventive control against both malicious and accidental exfiltration.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no data_leakage_prevention attestation collected
- attestation kind is <value>, expected "data_leakage_prevention"
- data_leakage_prevention attestation missing required field: <value>
- data_leakage_prevention review is overdue (next_review_due=<value>)
- data_leakage_prevention review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.12-data-leakage-prevention
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.12"
  nist_800_53:
  - "SC-7"
  - "AC-4"
```
