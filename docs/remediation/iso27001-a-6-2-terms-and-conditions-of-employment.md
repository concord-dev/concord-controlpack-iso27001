# Employment contracts state information security responsibilities

`ISO27001-A.6.2-terms-and-conditions-of-employment` · framework **iso27001** · severity **medium** · People Controls

## What this control checks

ISO/IEC 27001:2022 A.6.2 requires employment agreements to state personnel and organizational information security responsibilities. Concord verifies a cosigned attestation of the security-responsibilities clause, its coverage across contracts, and acknowledgement tracking.

## Why it matters

Contractual security obligations are what make security expectations enforceable throughout employment.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no employment_terms attestation collected
- attestation kind is <value>, expected "employment_terms"
- employment_terms attestation missing required field: <value>
- employment_terms review is overdue (next_review_due=<value>)
- employment_terms review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.6.2-terms-and-conditions-of-employment
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.6.2"
  nist_800_53:
  - "PS-6"
```
