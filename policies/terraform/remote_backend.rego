# METADATA
# title: Terraform state must use an S3 or GCS backend
# description: >
#   Local Terraform state is hard to protect, share safely, and recover. A
#   managed remote backend provides a central location for access controls and
#   state recovery.
# custom:
#   id: BND-TF-019
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.7]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(a)(2)(iv)]
#   remediation: |
#     Configure a terraform backend "s3" or backend "gcs" block. Do not use
#     the local backend for shared or production state.
#   fix_hint: change_value
#   references:
#     - https://developer.hashicorp.com/terraform/language/backend/s3
#     - https://developer.hashicorp.com/terraform/language/backend/gcs
package boundary.terraform.remote_backend

import data.boundary.lib

deny contains finding if {
	input.source == "hcl"
	some config in input.terraform.configurations
	count(config.backends) == 0
	finding := lib.finding(rego.metadata.chain(), config, {"backend": "not configured"})
}

deny contains finding if {
	input.source == "hcl"
	some config in input.terraform.configurations
	some backend in config.backends
	not backend.name in {"s3", "gcs"}
	finding := lib.finding(rego.metadata.chain(), backend, {"backend": backend.name})
}
