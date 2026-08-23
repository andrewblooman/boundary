# METADATA
# title: Google providers must apply default labels
# description: >
#   Resources without consistent ownership and environment labels are difficult
#   to inventory, audit, and govern. Provider-level defaults make labels apply
#   uniformly instead of relying on every individual resource.
# custom:
#   id: BND-TF-018
#   severity: MEDIUM
#   target: terraform
#   compliance:
#     soc2: [CC2.1, CC8.1]
#     dora: [Art.9.2]
#     nis2: [Art.21.2i]
#     hipaa: [164.308(a)(1)(ii)(A)]
#   remediation: |
#     Set a non-empty default_labels map on every Google provider configuration.
#   fix_hint: add_block
#   references:
#     - https://registry.terraform.io/providers/hashicorp/google/latest/docs/guides/provider_reference#default_labels
package boundary.terraform.google_default_labels

import data.boundary.lib

deny contains finding if {
	some provider in input.providers
	provider.name == "google"
	count(object.get(provider.values, "default_labels", {})) == 0
	finding := lib.finding(rego.metadata.chain(), provider, {"default_labels": "not configured"})
}
