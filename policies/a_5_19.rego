package concord.iso27001.a_5_19

import rego.v1

# ISO 27001:2022 A.5.19 — Supplier relationships, tier-1 certifications.

acceptable_cert_types := {"soc2", "iso27001", "iso27017", "iso27018"}

deny contains msg if {
    not input.attestation
    msg := "no vendor-register attestation collected"
}

deny contains msg if {
    input.attestation.kind != "vendor_register"
    msg := sprintf("attestation kind is %q, expected \"vendor_register\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "vendor-register attestation cosign signature did not verify"
}

deny contains msg if {
    some vendor in input.attestation.attested_fields.vendors
    vendor.tier == "tier_1"
    count(applicable_certs(vendor)) == 0
    msg := sprintf("tier-1 vendor %q has no acceptable security certification on file", [vendor.name])
}

deny contains msg if {
    some vendor in input.attestation.attested_fields.vendors
    vendor.tier == "tier_1"
    some cert in vendor.certifications
    cert.expired
    msg := sprintf("tier-1 vendor %q has an expired %s certification (expired %s)", [vendor.name, cert.type, cert.expires_at])
}

applicable_certs(vendor) := certs if {
    certs := [c |
        some c in vendor.certifications
        c.type in acceptable_cert_types
        not c.expired
    ]
}
