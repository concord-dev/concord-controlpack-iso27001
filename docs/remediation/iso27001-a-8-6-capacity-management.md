# Capacity demands are monitored and adjusted to needs

`ISO27001-A.8.6-capacity-management` · framework **iso27001** · severity **low** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.6 requires the use of resources to be monitored and adjusted in line with current and expected capacity requirements. Concord verifies a cosigned attestation of the monitoring approach, the capacity thresholds, and the scaling process.

## Why it matters

Capacity exhaustion is an availability risk that also degrades security controls (logging, monitoring) under load.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no capacity_management attestation collected
- attestation kind is <value>, expected "capacity_management"
- capacity_management attestation missing required field: <value>
- capacity_management review is overdue (next_review_due=<value>)
- capacity_management review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.6-capacity-management
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.6"
  nist_800_53:
  - "SC-5"
  - "AU-4"
```
