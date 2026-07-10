# Application security requirements are defined and tested

`ISO27001-A.8.26-application-security-requirements` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.26 requires information security requirements to be identified, specified, and approved when developing or acquiring applications. Concord verifies a cosigned attestation of the requirement categories, the definition process, and testing verification.

## Why it matters

Undefined appsec requirements produce untestable, insecure software; explicit requirements are the contract.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no appsec_requirements attestation collected
- attestation kind is <value>, expected "appsec_requirements"
- appsec_requirements attestation missing required field: <value>
- appsec_requirements review is overdue (next_review_due=<value>)
- appsec_requirements review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.26-application-security-requirements
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.26"
  nist_800_53:
  - "SA-8"
  - "SA-11"
```
