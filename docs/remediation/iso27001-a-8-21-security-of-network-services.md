# Network services are identified, monitored, and protected

`ISO27001-A.8.21-security-of-network-services` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.21 requires security mechanisms, service levels, and requirements of network services to be identified, implemented, and monitored. Concord verifies a cosigned attestation of the network-service inventory, the security mechanisms, and monitoring.

## Why it matters

Unmonitored network services are blind spots where compromise spreads laterally undetected.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no network_services_security attestation collected
- attestation kind is <value>, expected "network_services_security"
- network_services_security attestation missing required field: <value>
- network_services_security review is overdue (next_review_due=<value>)
- network_services_security review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.21-security-of-network-services
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.21"
  nist_800_53:
  - "SC-7"
  - "CA-3"
```
