# Access to source code is restricted to authorised personnel

`ISO27001-A.8.4-access-to-source-code` · framework **iso27001** · severity **medium** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.4 requires read and write access to source code, development tools, and libraries to be appropriately managed. Concord verifies a cosigned attestation of the access restrictions, the repository controls (branch protection, reviews), and the access-review process.

## Why it matters

Unrestricted source access enables backdoors and IP theft; repository access control is the control point.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no source_code_access attestation collected
- attestation kind is <value>, expected "source_code_access"
- source_code_access attestation missing required field: <value>
- source_code_access review is overdue (next_review_due=<value>)
- source_code_access review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.4-access-to-source-code
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.4"
  nist_800_53:
  - "AC-3"
  - "CM-5"
```
