# Access to information is restricted per the access control policy

`ISO27001-A.8.3-information-access-restriction` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.3 requires access to information and other associated assets to be restricted per the access control policy. Concord verifies a cosigned attestation of the access control policy, the enforcing mechanisms, and the access-review process.

## Why it matters

Least-privilege access restriction is the core preventive control against both external compromise and insider misuse.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no access_restriction attestation collected
- attestation kind is <value>, expected "access_restriction"
- access_restriction attestation missing required field: <value>
- access_restriction review is overdue (next_review_due=<value>)
- access_restriction review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.3-information-access-restriction
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.3"
  nist_800_53:
  - "AC-3"
  - "AC-6"
```
