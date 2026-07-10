# Appropriate contacts with special interest groups are maintained

`ISO27001-A.5.6-contact-with-special-interest-groups` · framework **iso27001** · severity **low** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.6 requires contact with special interest groups and professional security forums. Concord verifies a cosigned attestation of the groups engaged, the nature of participation, and how threat intel is shared internally.

## Why it matters

Peer and forum contacts are a primary source of early threat intelligence and remediation guidance.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no special_interest_groups attestation collected
- attestation kind is <value>, expected "special_interest_groups"
- special_interest_groups attestation missing required field: <value>
- special_interest_groups review is overdue (next_review_due=<value>)
- special_interest_groups review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.6-contact-with-special-interest-groups
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.6"
  nist_800_53:
  - "PM-15"
  - "SI-5"
```
