# Intellectual property rights are protected

`ISO27001-A.5.32-intellectual-property-rights` · framework **iso27001** · severity **low** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.32 requires appropriate procedures to protect intellectual property rights. Concord verifies a cosigned attestation of the IP protection measures, the software-license compliance process, and monitoring.

## Why it matters

License non-compliance and IP misuse carry legal and financial liability that A.5.32 is designed to prevent.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no ip_rights attestation collected
- attestation kind is <value>, expected "ip_rights"
- ip_rights attestation missing required field: <value>
- ip_rights review is overdue (next_review_due=<value>)
- ip_rights review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.32-intellectual-property-rights
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.32"
  nist_800_53:
  - "CM-10"
```
