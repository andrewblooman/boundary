# METADATA
# title: IAM bindings must not grant primitive owner or editor roles
# description: >
#   roles/owner and roles/editor are broad, pre-IAM legacy grants covering
#   almost every action on almost every resource in the project, organization,
#   or folder. A single compromised principal holding one of these roles has
#   near-total control; predefined or custom roles scoped to the actual job
#   keep the blast radius small.
# custom:
#   id: BND-TF-015
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.3]
#     dora: [Art.9.4]
#     nis2: [Art.21.2i]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Replace roles/owner or roles/editor with the narrowest predefined role
#     (or a custom role) that covers what the principal actually needs — e.g.
#     roles/cloudsql.client, roles/storage.objectAdmin. Reserve roles/owner
#     for a small, audited set of human break-glass identities.
#   fix_hint: change_value
#   references:
#     - https://cloud.google.com/iam/docs/understanding-roles#basic
package boundary.terraform.gcp_iam_primitive_role

import data.boundary.lib

primitive_roles := {"roles/owner", "roles/editor"}

privileged_iam_types := {
	"google_project_iam_member", "google_project_iam_binding",
	"google_organization_iam_member", "google_organization_iam_binding",
	"google_folder_iam_member", "google_folder_iam_binding",
}

deny contains finding if {
	some res in input.resources
	res.type in privileged_iam_types
	endswith(res.type, "_iam_member")
	res.values.role in primitive_roles
	finding := lib.finding(rego.metadata.chain(), res, {
		"role": res.values.role,
		"member": object.get(res.values, "member", ""),
	})
}

deny contains finding if {
	some res in input.resources
	res.type in privileged_iam_types
	endswith(res.type, "_iam_binding")
	res.values.role in primitive_roles
	finding := lib.finding(rego.metadata.chain(), res, {
		"role": res.values.role,
		"members": object.get(res.values, "members", []),
	})
}
