# Remote working security is enforced via policy and controls

`ISO27001-A.6.7-remote-working` · framework **iso27001** · severity **high** · People Controls

## What this control checks

ISO/IEC 27001:2022 A.6.7 requires security measures for personnel working remotely. Concord verifies a cosigned attestation of the remote-access controls, the device requirements, and the remote acceptable-use rules.

## Why it matters

Remote work expands the attack surface beyond the corporate perimeter; A.6.7 is the control that re-establishes it.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no remote_working_security attestation collected
- attestation kind is <value>, expected "remote_working_security"
- remote_working_security attestation missing required field: <value>
- remote_working_security review is overdue (next_review_due=<value>)
- remote_working_security review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.6.7-remote-working
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.6.7"
  nist_800_53:
  - "AC-17"
```
