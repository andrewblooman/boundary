# METADATA
# title: Firewall rules must not allow unrestricted ingress
# description: >
#   A google_compute_firewall allow rule with source_ranges 0.0.0.0/0 opens
#   the matched ports to the entire internet. Management ports and internal
#   services behind such rules are scanned and attacked within minutes of
#   creation.
# custom:
#   id: BND-TF-013
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(e)(1)]
#   remediation: |
#     Scope source_ranges to known networks (VPC ranges, VPN, office CIDRs) or
#     use source_tags / source_service_accounts. Front genuinely public
#     services with a load balancer plus Cloud Armor instead of an open
#     firewall rule.
#   fix_hint: change_value
#   references:
#     - https://cloud.google.com/firewall/docs/firewalls
package boundary.terraform.gcp_firewall_open_ingress

import data.boundary.lib

open_cidrs := {"0.0.0.0/0", "::/0"}

deny contains finding if {
	some res in input.resources
	res.type == "google_compute_firewall"
	upper(object.get(res.values, "direction", "INGRESS")) == "INGRESS"
	count(lib.as_array(object.get(res.values, "allow", []))) > 0
	some cidr in lib.as_array(object.get(res.values, "source_ranges", []))
	cidr in open_cidrs
	finding := lib.finding(rego.metadata.chain(), res, {
		"source_range": cidr,
		"allow": res.values.allow,
	})
}
