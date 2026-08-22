# METADATA
# title: Boundary shared policy helpers
# description: >
#   Builds the uniform finding object every Boundary policy returns. Policies
#   call lib.finding(rego.metadata.chain(), src, observed): the metadata chain
#   carries the policy's # METADATA block (id, severity, compliance mapping,
#   remediation, fix hint), src is the offending object from the adapter
#   (with its _src file/line), and observed records what was actually seen.
package boundary.lib

annotations(chain) := ann if {
	some entry in chain
	ann := entry.annotations
	ann.custom.id
}

finding(chain, src, observed) := f if {
	ann := annotations(chain)
	f := {
		"id": ann.custom.id,
		"severity": upper(object.get(ann.custom, "severity", "MEDIUM")),
		"title": object.get(ann, "title", ann.custom.id),
		"description": object.get(ann, "description", ""),
		"remediation": object.get(ann.custom, "remediation", ""),
		"fix_hint": object.get(ann.custom, "fix_hint", "review"),
		"compliance": object.get(ann.custom, "compliance", {}),
		"references": object.get(ann.custom, "references", []),
		"target": target(src),
		"observed": observed,
	}
}

target(src) := {
	"resource": resource_label(src),
	"file": object.get(src, ["_src", "file"], ""),
	"line": object.get(src, ["_src", "line"], 0),
}

resource_label(src) := src.address

resource_label(src) := src.name if not src.address

resource_label(src) := src.path if {
	not src.address
	not src.name
}

resource_label(src) := "" if {
	not src.address
	not src.name
	not src.path
}

# True when the value looks like a literal secret rather than a reference to
# a variable, secret store, or template placeholder.
is_literal_secret(value) if {
	is_string(value)
	trim_space(value) != ""
	not startswith(value, "${")
	not startswith(value, "$")
	not contains(value, "var.")
	not contains(value, "data.")
	not contains(value, "local.")
	not regex.match(`^\{\{.*\}\}$`, value)
}

# Attribute/env names that suggest the value is a credential.
secret_name_pattern := `(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)`

looks_like_secret_name(name) if regex.match(secret_name_pattern, name)

# HCL blocks parse to either a single object or a list of objects depending on
# repetition; normalize to a list so policies iterate uniformly.
as_array(null) := []

as_array(x) := x if {
	x != null
	is_array(x)
}

as_array(x) := [x] if {
	x != null
	not is_array(x)
}

is_true(true) := true

is_true("true") := true

# Does any of `res_values` reference the given resource address? Works on the
# unresolved "${aws_s3_bucket.data.id}" strings raw HCL parsing produces.
references(values, address) if contains(json.marshal(values), address)
