# METADATA
# title: RDS databases must enable storage encryption
# description: >
#   RDS storage encryption cannot be enabled after creation without a
#   snapshot-restore migration, so shipping an unencrypted instance bakes the
#   gap in. Snapshots and read replicas inherit the plaintext storage.
# custom:
#   id: BND-TF-006
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.7]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(a)(2)(iv)]
#   remediation: |
#     Set storage_encrypted = true on aws_db_instance / aws_rds_cluster
#     (optionally with kms_key_id for a customer-managed key). Aurora
#     Serverless v2 and provisioned clusters both support it at creation.
#   fix_hint: add_block
#   references:
#     - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html
package boundary.terraform.rds_encryption

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	res.type in {"aws_db_instance", "aws_rds_cluster"}
	not lib.is_true(object.get(res.values, "storage_encrypted", false))
	finding := lib.finding(rego.metadata.chain(), res, {"storage_encrypted": false})
}
