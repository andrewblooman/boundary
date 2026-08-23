# METADATA
# title: EC2 instances and subnets must not assign public IP addresses
# description: >
#   Public IP assignment exposes workloads directly to the internet and makes
#   accidental network exposure likely. Instances should receive private
#   addresses unless a tightly controlled ingress design requires otherwise.
# custom:
#   id: BND-TF-022
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(e)(1)]
#   remediation: |
#     Set map_public_ip_on_launch = false on aws_subnet and remove
#     associate_public_ip_address = true from aws_instance. Route controlled
#     inbound traffic through a load balancer or bastion where necessary.
#   fix_hint: change_value
#   references:
#     - https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Scenario2.html
package boundary.terraform.ec2_public_ip

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	res.type == "aws_subnet"
	lib.is_true(object.get(res.values, "map_public_ip_on_launch", false))
	finding := lib.finding(rego.metadata.chain(), res, {"map_public_ip_on_launch": true})
}

deny contains finding if {
	some res in input.resources
	res.type == "aws_instance"
	lib.is_true(object.get(res.values, "associate_public_ip_address", false))
	finding := lib.finding(rego.metadata.chain(), res, {"associate_public_ip_address": true})
}
