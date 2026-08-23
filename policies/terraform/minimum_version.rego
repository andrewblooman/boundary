# METADATA
# title: Terraform configurations must require version 1.15 or later
# description: >
#   Older Terraform versions do not provide the supported S3 lock-file
#   behavior required for safe remote state coordination.
# custom:
#   id: BND-TF-021
#   severity: MEDIUM
#   target: terraform
#   compliance:
#     soc2: [CC8.1]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(a)(2)(iv)]
#   remediation: |
#     Set required_version to >= 1.15 (optionally with an upper bound), for
#     example required_version = ">= 1.15, < 2.0".
#   fix_hint: change_value
#   references:
#     - https://developer.hashicorp.com/terraform/language/terraform#required_version
package boundary.terraform.minimum_version

import data.boundary.lib

deny contains finding if {
	input.source == "hcl"
	some config in input.terraform.configurations
	version := object.get(config, "required_version", "")
	not supports_1_15_or_later(version)
	finding := lib.finding(rego.metadata.chain(), config, {"required_version": version})
}

supports_1_15_or_later(version) if {
	regex.match(`(^|,)\s*(>=|=|~>)?\s*(1\.(1[5-9]|[2-9][0-9])|[2-9][0-9]*(\.[0-9]+){0,2})(\.[0-9]+)?\s*(,|$)`, version)
}
