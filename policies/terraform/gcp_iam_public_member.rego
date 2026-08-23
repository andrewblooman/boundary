# METADATA
# title: IAM bindings must not grant access to allUsers or allAuthenticatedUsers
# description: >
#   allUsers grants access to anyone on the internet, and
#   allAuthenticatedUsers grants it to any Google account holder, not just
#   your organization. Bound to any resource type — a project, a storage
#   bucket, a KMS key, a service account — either principal turns an IAM
#   grant into a public one.
# custom:
#   id: BND-TF-014
#   severity: CRITICAL
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.3]
#     nis2: [Art.21.2i]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Remove the allUsers / allAuthenticatedUsers member and grant the role to
#     specific users, groups, or service accounts instead. If public read
#     access is genuinely intended (e.g. static assets), scope it narrowly and
#     document the exception rather than binding it at a broad resource.
#   fix_hint: remove_block
#   references:
#     - https://cloud.google.com/storage/docs/access-control/making-data-public
package boundary.terraform.gcp_iam_public_member

import data.boundary.lib

public_principals := {"allUsers", "allAuthenticatedUsers"}

deny contains finding if {
	some res in input.resources
	endswith(res.type, "_iam_member")
	res.values.member in public_principals
	finding := lib.finding(rego.metadata.chain(), res, {
		"member": res.values.member,
		"role": object.get(res.values, "role", ""),
	})
}

deny contains finding if {
	some res in input.resources
	endswith(res.type, "_iam_binding")
	some member in lib.as_array(object.get(res.values, "members", []))
	member in public_principals
	finding := lib.finding(rego.metadata.chain(), res, {
		"member": member,
		"role": object.get(res.values, "role", ""),
	})
}
