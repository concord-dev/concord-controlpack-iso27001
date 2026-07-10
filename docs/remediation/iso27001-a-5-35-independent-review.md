# Independent reviews of information security are conducted

`ISO27001-A.5.35-independent-review` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.35 requires the information security approach to be reviewed independently at planned intervals. Concord verifies a cosigned attestation of the review scope, the reviewer's independence, and how findings are tracked to closure.

## Why it matters

Independent review is the check against self-graded security; auditors weight it heavily for objectivity.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no independent_review attestation collected
- attestation kind is <value>, expected "independent_review"
- independent_review attestation missing required field: <value>
- independent_review review is overdue (next_review_due=<value>)
- independent_review review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.35-independent-review
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.35"
  nist_800_53:
  - "CA-2"
  - "PM-14"
```
