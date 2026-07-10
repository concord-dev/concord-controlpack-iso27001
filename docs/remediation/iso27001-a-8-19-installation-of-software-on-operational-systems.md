# Software installation on operational systems is controlled

`ISO27001-A.8.19-installation-of-software-on-operational-systems` · framework **iso27001** · severity **medium** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.19 requires procedures and measures to securely manage software installation on operational systems. Concord verifies a cosigned attestation of the installation policy, the approval process, and the enforcement mechanism.

## Why it matters

Uncontrolled software installation introduces unvetted code and undermines the known-good baseline.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no software_installation_control attestation collected
- attestation kind is <value>, expected "software_installation_control"
- software_installation_control attestation missing required field: <value>
- software_installation_control review is overdue (next_review_due=<value>)
- software_installation_control review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.19-installation-of-software-on-operational-systems
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.19"
  nist_800_53:
  - "CM-11"
  - "CM-7"
```
