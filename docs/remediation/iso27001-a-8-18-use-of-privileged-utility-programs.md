# Privileged utility programs are restricted and tightly controlled

`ISO27001-A.8.18-use-of-privileged-utility-programs` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.18 requires the use of utility programs capable of overriding system and application controls to be restricted and tightly controlled. Concord verifies a cosigned attestation of the restricted utilities, the authorization process, and monitoring of their use.

## Why it matters

Privileged utilities can bypass every application-layer control; restricting and logging them is essential.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no privileged_utilities attestation collected
- attestation kind is <value>, expected "privileged_utilities"
- privileged_utilities attestation missing required field: <value>
- privileged_utilities review is overdue (next_review_due=<value>)
- privileged_utilities review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.18-use-of-privileged-utility-programs
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.18"
  nist_800_53:
  - "AC-6"
  - "CM-7"
```
