# Networks are segregated according to trust levels

`ISO27001-A.8.22-segregation-of-networks` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.22 requires groups of information services, users, and systems to be segregated in the organization's networks. Concord verifies a cosigned attestation of the segmentation design, the trust zones, and how segregation is enforced.

## Why it matters

Flat networks let one compromised host reach everything; segmentation contains lateral movement.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no network_segregation attestation collected
- attestation kind is <value>, expected "network_segregation"
- network_segregation attestation missing required field: <value>
- network_segregation review is overdue (next_review_due=<value>)
- network_segregation review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.22-segregation-of-networks
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.22"
  nist_800_53:
  - "SC-7"
```
