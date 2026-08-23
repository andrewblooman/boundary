# METADATA
# title: S3 Terraform backends must use lock files, not DynamoDB locks
# description: >
#   Terraform's S3 lock file is the current state-locking mechanism. Keeping a
#   DynamoDB lock table creates an unnecessary dependency on deprecated
#   locking behavior and makes state coordination harder to maintain.
# custom:
#   id: BND-TF-020
#   severity: MEDIUM
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC8.1]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(a)(2)(iv)]
#   remediation: |
#     Set use_lockfile = true in each S3 backend block and remove any
#     dynamodb_table setting.
#   fix_hint: change_value
#   references:
#     - https://developer.hashicorp.com/terraform/language/backend/s3#enabling-s3-state-locking
package boundary.terraform.s3_backend_locking

import data.boundary.lib

deny contains finding if {
	input.source == "hcl"
	some config in input.terraform.configurations
	some backend in config.backends
	backend.name == "s3"
	not lib.is_true(object.get(backend.values, "use_lockfile", false))
	finding := lib.finding(rego.metadata.chain(), backend, {"use_lockfile": false})
}

deny contains finding if {
	input.source == "hcl"
	some config in input.terraform.configurations
	some backend in config.backends
	backend.name == "s3"
	object.get(backend.values, "dynamodb_table", "") != ""
	finding := lib.finding(rego.metadata.chain(), backend, {
		"dynamodb_table": object.get(backend.values, "dynamodb_table", ""),
	})
}
