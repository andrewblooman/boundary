# METADATA
# title: Service accounts must not receive IAM administration roles
# description: >
#   Service-account administration and impersonation roles allow a workload to
#   create, manage, or act as other identities. A compromised workload holding
#   one can escalate its privileges across the project.
# custom:
#   id: BND-TF-024
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.3]
#     dora: [Art.9.4]
#     nis2: [Art.21.2i]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Replace the IAM administration role with the narrowest workload role.
#     Keep service account creation, key management, and impersonation grants
#     in audited human or dedicated deployment identities.
#   fix_hint: change_value
#   references:
#     - https://cloud.google.com/iam/docs/service-account-overview
package boundary.terraform.gcp_service_account_admin

import data.boundary.lib

sensitive_roles := {
	"roles/iam.serviceAccountAdmin",
	"roles/iam.serviceAccountKeyAdmin",
	"roles/iam.serviceAccountTokenCreator",
	"roles/iam.serviceAccountUser",
	"roles/iam.securityAdmin",
}

iam_types := {
	"google_project_iam_member", "google_project_iam_binding",
	"google_organization_iam_member", "google_organization_iam_binding",
	"google_folder_iam_member", "google_folder_iam_binding",
}

deny contains finding if {
	some res in input.resources
	res.type in iam_types
	endswith(res.type, "_iam_member")
	res.values.role in sensitive_roles
	member := object.get(res.values, "member", "")
	startswith(member, "serviceAccount:")
	finding := lib.finding(rego.metadata.chain(), res, {
		"role": res.values.role,
		"member": member,
	})
}

deny contains finding if {
	some res in input.resources
	res.type in iam_types
	endswith(res.type, "_iam_binding")
	res.values.role in sensitive_roles
	some member in lib.as_array(object.get(res.values, "members", []))
	startswith(member, "serviceAccount:")
	finding := lib.finding(rego.metadata.chain(), res, {
		"role": res.values.role,
		"member": member,
	})
}
