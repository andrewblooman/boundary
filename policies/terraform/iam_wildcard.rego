# METADATA
# title: IAM policies must not grant wildcard action on wildcard resource
# description: >
#   An Allow statement with Action "*" on Resource "*" is full administrative
#   access. Any principal that can assume it — or any leaked credential —
#   controls the entire account.
# custom:
#   id: BND-TF-004
#   severity: CRITICAL
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.3]
#     dora: [Art.9.4]
#     nis2: [Art.21.2i]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Scope the statement to the specific actions and resource ARNs the workload
#     needs (least privilege). If broad access is genuinely required, attach the
#     AWS-managed AdministratorAccess policy to a break-glass role instead of
#     embedding "*"/"*" in first-party policy documents.
#   fix_hint: change_value
#   references:
#     - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege
package boundary.terraform.iam_wildcard

import data.boundary.lib

policy_types := {
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
}

deny contains finding if {
	some res in input.resources
	res.type in policy_types
	doc := policy_doc(res)
	some stmt in lib.as_array(object.get(doc, "Statement", []))
	object.get(stmt, "Effect", "Allow") == "Allow"
	"*" in lib.as_array(object.get(stmt, "Action", []))
	"*" in lib.as_array(object.get(stmt, "Resource", []))
	finding := lib.finding(rego.metadata.chain(), res, {"statement": stmt})
}

policy_doc(res) := doc if {
	raw := res.values.policy
	is_string(raw)
	json.is_valid(raw)
	doc := json.unmarshal(raw)
}

policy_doc(res) := doc if {
	doc := res.values.policy
	is_object(doc)
}
