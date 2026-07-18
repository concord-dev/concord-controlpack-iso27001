package concord.iso27001.a_8_22_segregation_of_networks

import rego.v1

# ISO/IEC 27001:2022 A.8.22 — Segregation of networks. Groups of information
# services, users and information systems must be segregated in the
# organisation's networks. Concord verifies this technically over the network
# ACL inventory (input.network_acls.acls[]): each ACL must carry an explicit
# deny-all catch-all on BOTH directions, so traffic not expressly permitted is
# dropped and segments are isolated by default rather than open. Fail-closed: no
# evidence, or no ACLs, denies. Adapted from the PCI DSS 1.4.1 NSC pattern.

deny contains msg if {
	not input.network_acls
	msg := "no network-ACL evidence collected — network segregation cannot be demonstrated (ISO 27001 A.8.22)"
}

deny contains msg if {
	input.network_acls
	count(input.network_acls.acls) == 0
	msg := "no network ACLs found — network segments are not isolated by any boundary control (ISO 27001 A.8.22)"
}

deny contains msg if {
	some acl in input.network_acls.acls
	not has_default_deny(acl, false)
	msg := sprintf("network ACL %q has no explicit inbound deny-all rule — the segment is not isolated by default (ISO 27001 A.8.22)", [acl.id])
}

deny contains msg if {
	some acl in input.network_acls.acls
	not has_default_deny(acl, true)
	msg := sprintf("network ACL %q has no explicit outbound deny-all rule — the segment boundary is open on egress (ISO 27001 A.8.22)", [acl.id])
}

has_default_deny(acl, egress_flag) if {
	some entry in acl.entries
	entry.egress == egress_flag
	entry.action == "deny"
	entry.cidr == "0.0.0.0/0"
	catch_all_protocol(entry)
}

catch_all_protocol(entry) if entry.protocol == "-1"

catch_all_protocol(entry) if entry.protocol == "all"
