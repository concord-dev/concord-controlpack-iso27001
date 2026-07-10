# Reporting channel for information security events is documented

`ISO27001-A.6.8-information-security-event-reporting` · framework **iso27001** · severity **medium** · People Controls

## What this control checks

ISO/IEC 27001:2022 A.6.8 requires a mechanism for personnel to report observed or suspected information security events timely. Concord verifies a cosigned attestation of the reporting channel, the reporting timeframes, and how awareness of it is communicated.

## Why it matters

Fast human reporting is often the earliest incident signal; a documented, known channel is what enables it.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no event_reporting attestation collected
- attestation kind is <value>, expected "event_reporting"
- event_reporting attestation missing required field: <value>
- event_reporting review is overdue (next_review_due=<value>)
- event_reporting review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.6.8-information-security-event-reporting
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.6.8"
  nist_800_53:
  - "IR-6"
```
