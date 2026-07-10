# Assets are returned upon termination of employment

`ISO27001-A.5.11-return-of-assets` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.11 requires personnel to return organizational assets on termination or change of employment. Concord verifies a cosigned attestation of the return process, the asset types tracked, and its integration with offboarding.

## Why it matters

Unreturned laptops, tokens, and credentials are a frequent source of post-termination data exposure.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no asset_return attestation collected
- attestation kind is <value>, expected "asset_return"
- asset_return attestation missing required field: <value>
- asset_return review is overdue (next_review_due=<value>)
- asset_return review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.11-return-of-assets
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.11"
  nist_800_53:
  - "PS-4"
  - "PS-5"
```
