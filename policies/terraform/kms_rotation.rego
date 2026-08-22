# METADATA
# title: KMS keys must enable automatic rotation
# description: >
#   Without rotation, a customer-managed KMS key encrypts years of data under
#   one backing key: a single compromise exposes everything ever encrypted
#   with it, and compliance frameworks expect periodic rotation.
# custom:
#   id: BND-TF-009
#   severity: MEDIUM
#   target: terraform
#   compliance:
#     soc2: [CC6.1]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(a)(2)(iv)]
#   remediation: |
#     Set enable_key_rotation = true on aws_kms_key (symmetric keys only;
#     asymmetric keys need manual rotation via aliases).
#   fix_hint: add_block
#   references:
#     - https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html
package boundary.terraform.kms_rotation

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	res.type == "aws_kms_key"
	symmetric(res)
	not lib.is_true(object.get(res.values, "enable_key_rotation", false))
	finding := lib.finding(rego.metadata.chain(), res, {"enable_key_rotation": false})
}

symmetric(res) if {
	spec := object.get(res.values, "customer_master_key_spec", "SYMMETRIC_DEFAULT")
	spec == "SYMMETRIC_DEFAULT"
}
