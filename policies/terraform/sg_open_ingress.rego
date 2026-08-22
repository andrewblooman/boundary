# METADATA
# title: Security groups must not allow unrestricted ingress
# description: >
#   An ingress rule open to 0.0.0.0/0 (or ::/0) exposes the attached workloads
#   to the whole internet. Management ports and databases behind such rules are
#   scanned and attacked within minutes.
# custom:
#   id: BND-TF-003
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(e)(1)]
#   remediation: |
#     Restrict cidr_blocks to known networks (VPN, office ranges, peered VPCs)
#     or use security-group references. For admin access prefer SSM Session
#     Manager over exposing port 22/3389.
#   fix_hint: change_value
#   references:
#     - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html
package boundary.terraform.sg_open_ingress

import data.boundary.lib

open_cidrs := {"0.0.0.0/0", "::/0"}

deny contains finding if {
	some res in input.resources
	res.type == "aws_security_group"
	some rule in lib.as_array(object.get(res.values, "ingress", []))
	cidr := open_cidr(rule)
	finding := lib.finding(rego.metadata.chain(), res, {
		"cidr": cidr,
		"from_port": object.get(rule, "from_port", null),
		"to_port": object.get(rule, "to_port", null),
	})
}

deny contains finding if {
	some res in input.resources
	res.type in {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}
	is_ingress(res)
	cidr := open_cidr(res.values)
	finding := lib.finding(rego.metadata.chain(), res, {
		"cidr": cidr,
		"from_port": object.get(res.values, "from_port", null),
		"to_port": object.get(res.values, "to_port", null),
	})
}

is_ingress(res) if res.type == "aws_vpc_security_group_ingress_rule"

is_ingress(res) if {
	res.type == "aws_security_group_rule"
	res.values.type == "ingress"
}

open_cidr(rule) := cidr if {
	some cidr in lib.as_array(object.get(rule, "cidr_blocks", []))
	cidr in open_cidrs
}

open_cidr(rule) := cidr if {
	not object.get(rule, "cidr_blocks", null)
	some cidr in lib.as_array(object.get(rule, "ipv6_cidr_blocks", []))
	cidr in open_cidrs
}

open_cidr(rule) := cidr if {
	not object.get(rule, "cidr_blocks", null)
	not object.get(rule, "ipv6_cidr_blocks", null)
	cidr := object.get(rule, "cidr_ipv4", "")
	cidr in open_cidrs
}
