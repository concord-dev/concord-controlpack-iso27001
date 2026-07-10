# Evidence collection during incidents follows forensics procedures

`ISO27001-A.5.28-collection-of-evidence` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.28 requires procedures for the identification, collection, and preservation of evidence. Concord verifies a cosigned attestation of the forensic procedures, the chain-of-custody controls, and the collection tooling.

## Why it matters

Improperly collected evidence is inadmissible and can taint an entire investigation or legal action.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no evidence_collection attestation collected
- attestation kind is <value>, expected "evidence_collection"
- evidence_collection attestation missing required field: <value>
- evidence_collection review is overdue (next_review_due=<value>)
- evidence_collection review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.28-collection-of-evidence
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.28"
  nist_800_53:
  - "IR-4"
  - "AU-11"
```
