package concord.iso27001.a_8_3_information_access_restriction

import rego.v1

# ISO/IEC 27001:2022 A.8.3 — Information access restriction. Access to
# information and other associated assets must be restricted in accordance with
# the access control policy (least privilege / need-to-know). Concord verifies
# this technically over the IAM policy inventory
# (input.iam_policies.identities[].attached_policies[]): no identity may hold a
# standing full-admin grant — neither the AWS-managed AdministratorAccess policy
# nor an Allow of Action "*" on Resource "*". Fail-closed: no evidence is a
# denial. Adapted from the PCI DSS 7.1 / CIS AWS 1.16 least-privilege pattern.

deny contains msg if {
	not input.iam_policies
	msg := "no IAM policy evidence collected — cannot demonstrate access is restricted to least privilege (ISO 27001 A.8.3)"
}

deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	p.policy_name == "AdministratorAccess"
	msg := sprintf("IAM %s %q is attached to AdministratorAccess — full-admin access is not restricted per the access control policy (ISO 27001 A.8.3)", [identity_type(id), id.name])
}

deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	action_is_wildcard(stmt)
	resource_is_wildcard(stmt)
	msg := sprintf("IAM %s %q attaches policy %q allowing Action \"*\" on Resource \"*\" — grant is broader than the access control policy permits (ISO 27001 A.8.3)", [identity_type(id), id.name, p.policy_name])
}

identity_type(id) := id.type

identity_type(id) := "identity" if not id.type

action_is_wildcard(stmt) if stmt.Action == "*"

action_is_wildcard(stmt) if {
	some a in stmt.Action
	a == "*"
}

resource_is_wildcard(stmt) if stmt.Resource == "*"

resource_is_wildcard(stmt) if {
	some r in stmt.Resource
	r == "*"
}
