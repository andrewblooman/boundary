# METADATA
# title: Load balancer listeners must not serve plain HTTP
# description: >
#   An HTTP listener that is not a redirect sends traffic — including session
#   cookies and credentials — unencrypted. TLS termination belongs at the
#   listener, with port 80 kept only as a 301 redirect to HTTPS.
# custom:
#   id: BND-TF-010
#   severity: MEDIUM
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.7]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(e)(1)]
#   remediation: |
#     Change the listener to HTTPS with an ACM certificate and a modern SSL
#     policy. If port 80 must stay open, make its default_action a redirect
#     to the HTTPS listener.
#   fix_hint: change_value
#   references:
#     - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html
package boundary.terraform.lb_insecure_listener

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	res.type in {"aws_lb_listener", "aws_alb_listener"}
	upper(object.get(res.values, "protocol", "")) == "HTTP"
	not redirects(res)
	finding := lib.finding(rego.metadata.chain(), res, {
		"protocol": "HTTP",
		"port": object.get(res.values, "port", null),
	})
}

redirects(res) if {
	some action in lib.as_array(object.get(res.values, "default_action", []))
	action.type == "redirect"
}
