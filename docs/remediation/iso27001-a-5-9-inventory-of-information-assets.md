# Inventory of information assets is maintained and up to date

`ISO27001-A.5.9-inventory-of-information-assets` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.9 requires an inventory of information and other associated assets, including owners. Concord verifies a cosigned attestation of the inventory scope, owner assignment, and the review cadence keeping it current.

## Why it matters

You cannot protect what you have not inventoried; the asset inventory underpins classification, access, and risk decisions.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no asset_inventory attestation collected
- attestation kind is <value>, expected "asset_inventory"
- asset_inventory attestation missing required field: <value>
- asset_inventory review is overdue (next_review_due=<value>)
- asset_inventory review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.9-inventory-of-information-assets
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.9"
  nist_800_53:
  - "CM-8"
  - "PM-5"
```
