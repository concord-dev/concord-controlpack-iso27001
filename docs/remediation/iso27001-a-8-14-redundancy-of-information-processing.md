# Availability is maintained via redundancy in critical components

`ISO27001-A.8.14-redundancy-of-information-processing` · framework **iso27001** · severity **medium** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.14 requires information processing facilities to be implemented with redundancy sufficient to meet availability requirements. Concord verifies a cosigned attestation of the redundant components, the availability targets, and failover testing.

## Why it matters

Single points of failure turn routine faults into outages; tested redundancy is what meets availability commitments.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no redundancy attestation collected
- attestation kind is <value>, expected "redundancy"
- redundancy attestation missing required field: <value>
- redundancy review is overdue (next_review_due=<value>)
- redundancy review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.14-redundancy-of-information-processing
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.14"
  nist_800_53:
  - "CP-2"
  - "SC-6"
```
