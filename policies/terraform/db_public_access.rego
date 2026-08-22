# METADATA
# title: Databases must not be publicly accessible
# description: >
#   publicly_accessible = true gives the database a public IP and DNS name.
#   Combined with a permissive security group this puts the data store one
#   credential-stuffing attack away from the internet.
# custom:
#   id: BND-TF-007
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.3]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(e)(1)]
#   remediation: |
#     Set publicly_accessible = false and place the database in private subnets.
#     Reach it via VPN, SSM port forwarding, or an application-tier proxy.
#   fix_hint: change_value
#   references:
#     - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
package boundary.terraform.db_public_access

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	res.type in {"aws_db_instance", "aws_redshift_cluster", "aws_rds_cluster_instance"}
	lib.is_true(object.get(res.values, "publicly_accessible", false))
	finding := lib.finding(rego.metadata.chain(), res, {"publicly_accessible": true})
}
