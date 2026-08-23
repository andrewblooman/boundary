# METADATA
# title: AWS providers must apply default tags
# description: >
#   Resources without consistent ownership and environment tags are difficult
#   to inventory, audit, and govern. Provider-level defaults make tags apply
#   uniformly instead of relying on every individual resource.
# custom:
#   id: BND-TF-017
#   severity: MEDIUM
#   target: terraform
#   compliance:
#     soc2: [CC2.1, CC8.1]
#     dora: [Art.9.2]
#     nis2: [Art.21.2i]
#     hipaa: [164.308(a)(1)(ii)(A)]
#   remediation: |
#     Add a default_tags block with a non-empty tags map to every AWS provider
#     configuration.
#   fix_hint: add_block
#   references:
#     - https://registry.terraform.io/providers/hashicorp/aws/latest/docs#default_tags-configuration-block
package boundary.terraform.aws_default_tags

import data.boundary.lib

deny contains finding if {
	some provider in input.providers
	provider.name == "aws"
	not has_default_tags(provider)
	finding := lib.finding(rego.metadata.chain(), provider, {"default_tags": "not configured"})
}

has_default_tags(provider) if {
	some block in lib.as_array(object.get(provider.values, "default_tags", []))
	count(object.get(block, "tags", {})) > 0
}
