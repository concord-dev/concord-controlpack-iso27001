# ICT supply chain information security risks are managed

`ISO27001-A.5.21-managing-information-security-in-ict-supply-chain` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.21 requires managing information security risks in the ICT supply chain. Concord verifies a cosigned attestation of the identified supply-chain risks, how controls flow down to subcontractors, and ongoing monitoring.

## Why it matters

Compromise of an upstream ICT supplier propagates to every downstream customer; flow-down controls contain that blast radius.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no ict_supply_chain attestation collected
- attestation kind is <value>, expected "ict_supply_chain"
- ict_supply_chain attestation missing required field: <value>
- ict_supply_chain review is overdue (next_review_due=<value>)
- ict_supply_chain review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.21-managing-information-security-in-ict-supply-chain
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.21"
  nist_800_53:
  - "SR-3"
  - "SR-5"
```
