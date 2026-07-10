# System clocks are synchronised to an approved reference time source

`ISO27001-A.8.17-clock-synchronisation` · framework **iso27001** · severity **low** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.17 requires clocks of information processing systems to be synchronised to approved time sources. Concord verifies a cosigned attestation of the reference time source, the synchronisation protocol, and coverage across systems.

## Why it matters

Unsynchronised clocks make log correlation and forensic timelines unreliable across systems.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no clock_synchronisation attestation collected
- attestation kind is <value>, expected "clock_synchronisation"
- clock_synchronisation attestation missing required field: <value>
- clock_synchronisation review is overdue (next_review_due=<value>)
- clock_synchronisation review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.17-clock-synchronisation
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.17"
  nist_800_53:
  - "AU-8"
```
