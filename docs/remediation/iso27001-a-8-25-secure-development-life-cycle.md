# SDLC includes security activities at each phase

`ISO27001-A.8.25-secure-development-life-cycle` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.25 requires rules for the secure development of software and systems to be established and applied. Concord verifies a cosigned attestation of the SDLC phases, the per-phase security gates, and the supporting tooling.

## Why it matters

Security built into each SDLC phase is far cheaper and stronger than remediation after release.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no secure_sdlc attestation collected
- attestation kind is <value>, expected "secure_sdlc"
- secure_sdlc attestation missing required field: <value>
- secure_sdlc review is overdue (next_review_due=<value>)
- secure_sdlc review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.25-secure-development-life-cycle
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.25"
  nist_800_53:
  - "SA-3"
  - "SA-15"
```
