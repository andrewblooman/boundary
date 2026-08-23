# METADATA
# title: Avoid creating downloadable service account keys
# description: >
#   A google_service_account_key produces a long-lived JSON private key that
#   Terraform writes to state and that, once exported, cannot be revoked
#   short of deleting the key entirely. Workload Identity Federation, Workload
#   Identity (GKE), or attached service accounts (Compute/Cloud Run) all give
#   the same access without a static credential to leak or rotate.
# custom:
#   id: BND-TF-016
#   severity: MEDIUM
#   target: terraform
#   compliance:
#     soc2: [CC6.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2j]
#     hipaa: [164.312(a)(2)(i)]
#   remediation: |
#     Remove the google_service_account_key resource and use Workload Identity
#     Federation (external workloads), GKE Workload Identity, or an attached
#     service account (Compute Engine / Cloud Run / Cloud Functions) instead.
#     If a key is unavoidable (e.g. a third-party SaaS integration), store it
#     in Secret Manager, restrict who can read the resource, and rotate it on
#     a schedule.
#   fix_hint: review
#   references:
#     - https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys
package boundary.terraform.gcp_service_account_key

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	res.type == "google_service_account_key"
	finding := lib.finding(rego.metadata.chain(), res, {"resource": res.address})
}
