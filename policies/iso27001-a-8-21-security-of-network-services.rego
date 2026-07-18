package concord.iso27001.a_8_21_security_of_network_services

import rego.v1

# ISO/IEC 27001:2022 A.8.21 — Security of network services. Security mechanisms,
# service levels and management requirements of network services must be
# identified, implemented and monitored. Concord verifies this technically over
# the security-group inventory (input.security_groups.groups[]): no group may
# expose a sensitive administrative or database service port to the entire
# internet (0.0.0.0/0). Fail-closed: no evidence is a denial.

sensitive_ports := {22, 3389, 3306, 5432, 6379, 9200, 27017}

deny contains msg if {
	not input.security_groups
	msg := "no security-group evidence collected — network service exposure cannot be demonstrated as controlled (ISO 27001 A.8.21)"
}

deny contains msg if {
	some sg in input.security_groups.groups
	some rule in sg.ingress_rules
	rule.cidr == "0.0.0.0/0"
	some port in sensitive_ports
	port_in_range(port, rule)
	msg := sprintf("security group %q exposes sensitive service port %d to 0.0.0.0/0 — network service is not protected (ISO 27001 A.8.21)", [sg.id, port])
}

port_in_range(port, rule) if {
	rule.from_port <= port
	rule.to_port >= port
}
