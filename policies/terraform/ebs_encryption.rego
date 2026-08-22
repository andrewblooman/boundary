# METADATA
# title: EBS volumes and instance block devices must be encrypted
# description: >
#   Unencrypted EBS volumes expose data through snapshots, detached volumes,
#   and cross-account sharing. Encryption at rest is free and has no
#   measurable performance cost on modern instance types.
# custom:
#   id: BND-TF-005
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.7]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(a)(2)(iv)]
#   remediation: |
#     Set encrypted = true on aws_ebs_volume and on every root_block_device /
#     ebs_block_device block, or enable EBS encryption by default for the region
#     with aws_ebs_encryption_by_default.
#   fix_hint: add_block
#   references:
#     - https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html
package boundary.terraform.ebs_encryption

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	res.type == "aws_ebs_volume"
	not lib.is_true(object.get(res.values, "encrypted", false))
	finding := lib.finding(rego.metadata.chain(), res, {"encrypted": false})
}

deny contains finding if {
	some res in input.resources
	res.type == "aws_instance"
	some block_key in {"root_block_device", "ebs_block_device"}
	some device in lib.as_array(object.get(res.values, block_key, []))
	not lib.is_true(object.get(device, "encrypted", false))
	finding := lib.finding(rego.metadata.chain(), res, {
		"block": block_key,
		"encrypted": false,
	})
}
