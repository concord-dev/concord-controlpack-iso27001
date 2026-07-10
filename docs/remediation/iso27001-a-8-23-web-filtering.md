# Web filtering limits access to malicious sites

`ISO27001-A.8.23-web-filtering` · framework **iso27001** · severity **medium** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.23 requires access to external websites to be managed to reduce exposure to malicious content. Concord verifies a cosigned attestation of the web-filtering solution, the blocked categories, and coverage.

## Why it matters

Web filtering blocks a common malware-delivery and phishing vector before it reaches the endpoint.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no web_filtering attestation collected
- attestation kind is <value>, expected "web_filtering"
- web_filtering attestation missing required field: <value>
- web_filtering review is overdue (next_review_due=<value>)
- web_filtering review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.23-web-filtering
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.23"
  nist_800_53:
  - "SC-7"
  - "SI-3"
```
