# METADATA
# title: EC2 instances must require IMDSv2
# description: >
#   IMDSv1 can expose instance-role credentials when an application is
#   vulnerable to server-side request forgery. Requiring IMDSv2 adds a
#   session-oriented token that reduces this risk.
# custom:
#   id: BND-TF-023
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Add metadata_options { http_tokens = "required" } to every aws_instance.
#     Confirm applications use IMDSv2 before enforcing the setting on legacy
#     workloads.
#   fix_hint: add_block
#   references:
#     - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
package boundary.terraform.ec2_imdsv2

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	res.type == "aws_instance"
	not requires_imdsv2(res)
	finding := lib.finding(rego.metadata.chain(), res, {"http_tokens": "optional or unset"})
}

requires_imdsv2(res) if {
	some options in lib.as_array(object.get(res.values, "metadata_options", []))
	lower(object.get(options, "http_tokens", "")) == "required"
}
