# User endpoint devices are inventoried and managed via MDM

`ISO27001-A.8.1-user-endpoint-devices` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.1 requires information on user endpoint devices to be protected. Concord verifies a cosigned attestation of the device inventory, MDM enforcement, and the endpoint disk-encryption requirement.

## Why it matters

Unmanaged, unencrypted endpoints are a leading cause of ePHI/PII loss; MDM and encryption are the baseline endpoint controls.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no endpoint_management attestation collected
- attestation kind is <value>, expected "endpoint_management"
- endpoint_management attestation missing required field: <value>
- endpoint_management review is overdue (next_review_due=<value>)
- endpoint_management review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.1-user-endpoint-devices
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.1"
  nist_800_53:
  - "CM-8"
  - "AC-19"
```
