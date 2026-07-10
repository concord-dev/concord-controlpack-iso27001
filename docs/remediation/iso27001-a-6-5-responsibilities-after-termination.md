# Responsibilities remaining after termination are defined

`ISO27001-A.6.5-responsibilities-after-termination` · framework **iso27001** · severity **medium** · People Controls

## What this control checks

ISO/IEC 27001:2022 A.6.5 requires information security responsibilities that remain valid after termination to be defined, enforced, and communicated. Concord verifies a cosigned attestation of the continuing obligations, their enforcement, and communication at exit.

## Why it matters

Confidentiality and IP obligations that survive employment are only enforceable if defined and acknowledged at exit.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no post_termination_responsibilities attestation collected
- attestation kind is <value>, expected "post_termination_responsibilities"
- post_termination_responsibilities attestation missing required field: <value>
- post_termination_responsibilities review is overdue (next_review_due=<value>)
- post_termination_responsibilities review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.6.5-responsibilities-after-termination
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.6.5"
  nist_800_53:
  - "PS-4"
  - "PS-6"
```
