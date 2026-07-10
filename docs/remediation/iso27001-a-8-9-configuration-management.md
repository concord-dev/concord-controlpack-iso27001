# Configuration baselines exist and drift is detected

`ISO27001-A.8.9-configuration-management` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.9 requires configurations, including security configurations, to be established, documented, implemented, monitored, and reviewed. Concord verifies a cosigned attestation of the baseline definitions, the drift-detection mechanism, and enforcement.

## Why it matters

Configuration drift silently erodes hardening; baselines plus drift detection keep systems in a known-good state.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no configuration_management attestation collected
- attestation kind is <value>, expected "configuration_management"
- configuration_management attestation missing required field: <value>
- configuration_management review is overdue (next_review_due=<value>)
- configuration_management review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.9-configuration-management
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.9"
  nist_800_53:
  - "CM-2"
  - "CM-6"
```
