# Suppliers are monitored, reviewed, and managed for compliance

`ISO27001-A.5.22-monitoring-review-change-mgmt-supplier` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.22 requires regular monitoring, review, and change management of supplier services. Concord verifies a cosigned attestation of the monitoring cadence, the review criteria, and how supplier changes are managed.

## Why it matters

Supplier security drifts over time; periodic review catches degraded controls before they become incidents.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no supplier_monitoring attestation collected
- attestation kind is <value>, expected "supplier_monitoring"
- supplier_monitoring attestation missing required field: <value>
- supplier_monitoring review is overdue (next_review_due=<value>)
- supplier_monitoring review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.22-monitoring-review-change-mgmt-supplier
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.22"
  nist_800_53:
  - "SR-6"
  - "SA-9"
```
