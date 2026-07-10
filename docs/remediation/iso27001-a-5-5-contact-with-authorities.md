# Appropriate contacts with relevant authorities are maintained

`ISO27001-A.5.5-contact-with-authorities` · framework **iso27001** · severity **low** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.5 requires maintaining contact with relevant authorities. Concord verifies a cosigned attestation identifying the relevant authorities, the contact process, and the triggers for escalation.

## Why it matters

Pre-established authority contacts (regulators, CERTs, law enforcement) shorten breach-notification and response timelines.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no authority_contacts attestation collected
- attestation kind is <value>, expected "authority_contacts"
- authority_contacts attestation missing required field: <value>
- authority_contacts review is overdue (next_review_due=<value>)
- authority_contacts review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.5-contact-with-authorities
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.5"
  nist_800_53:
  - "IR-6"
```
