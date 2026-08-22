package boundary.kubernetes_test

import data.boundary.kubernetes

manifest(kind, spec) := {"kind": "kubernetes", "file": "deploy.yaml", "objects": [{
	"apiVersion": "apps/v1", "kind": kind, "name": "app",
	"manifest": {"apiVersion": "apps/v1", "kind": kind, "metadata": {"name": "app"}, "spec": spec},
	"_src": {"file": "deploy.yaml", "line": 1},
}]}

deployment(pod_spec) := manifest("Deployment", {"template": {"spec": pod_spec}})

secure_container := {
	"name": "app",
	"image": "registry.local/app:1.0.0@sha256:abc",
	"resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
	"securityContext": {
		"runAsNonRoot": true,
		"allowPrivilegeEscalation": false,
		"capabilities": {"drop": ["ALL"]},
	},
}

test_privileged_flagged if {
	count(kubernetes.privileged.deny) == 1 with input as deployment({"containers": [{"name": "app", "securityContext": {"privileged": true}}]})
}

test_unprivileged_ok if {
	count(kubernetes.privileged.deny) == 0 with input as deployment({"containers": [secure_container]})
}

test_privilege_escalation_default_flagged if {
	count(kubernetes.privilege_escalation.deny) == 1 with input as deployment({"containers": [{"name": "app"}]})
}

test_privilege_escalation_disabled_ok if {
	count(kubernetes.privilege_escalation.deny) == 0 with input as deployment({"containers": [secure_container]})
}

test_run_as_root_default_flagged if {
	count(kubernetes.run_as_root.deny) == 1 with input as deployment({"containers": [{"name": "app"}]})
}

test_run_as_nonroot_pod_level_ok if {
	count(kubernetes.run_as_root.deny) == 0 with input as deployment({
		"securityContext": {"runAsNonRoot": true},
		"containers": [{"name": "app"}],
	})
}

test_runasuser_zero_flagged if {
	count(kubernetes.run_as_root.deny) == 1 with input as deployment({"containers": [{
		"name": "app",
		"securityContext": {"runAsNonRoot": true, "runAsUser": 0},
	}]})
}

test_hostpath_flagged if {
	count(kubernetes.host_path.deny) == 1 with input as deployment({
		"volumes": [{"name": "h", "hostPath": {"path": "/etc"}}],
		"containers": [{"name": "app"}],
	})
}

test_emptydir_ok if {
	count(kubernetes.host_path.deny) == 0 with input as deployment({
		"volumes": [{"name": "tmp", "emptyDir": {}}],
		"containers": [{"name": "app"}],
	})
}

test_hostnetwork_flagged if {
	count(kubernetes.host_namespaces.deny) == 1 with input as deployment({
		"hostNetwork": true,
		"containers": [{"name": "app"}],
	})
}

test_missing_limits_flagged if {
	count(kubernetes.resource_limits.deny) == 1 with input as deployment({"containers": [{"name": "app"}]})
}

test_limits_present_ok if {
	count(kubernetes.resource_limits.deny) == 0 with input as deployment({"containers": [secure_container]})
}

test_latest_image_flagged if {
	count(kubernetes.image_tag.deny) == 1 with input as deployment({"containers": [{"name": "app", "image": "app:latest"}]})
}

test_untagged_registry_port_flagged if {
	count(kubernetes.image_tag.deny) == 1 with input as deployment({"containers": [{"name": "app", "image": "registry.local:5000/app"}]})
}

test_pinned_image_ok if {
	count(kubernetes.image_tag.deny) == 0 with input as deployment({"containers": [secure_container]})
}

test_sys_admin_capability_flagged if {
	count(kubernetes.capabilities.deny) == 1 with input as deployment({"containers": [{
		"name": "app",
		"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}},
	}]})
}

test_net_bind_ok if {
	count(kubernetes.capabilities.deny) == 0 with input as deployment({"containers": [{
		"name": "app",
		"securityContext": {"capabilities": {"add": ["NET_BIND_SERVICE"]}},
	}]})
}

test_default_namespace_flagged if {
	count(kubernetes.default_namespace.deny) == 1 with input as deployment({"containers": [{"name": "app"}]})
}

test_explicit_namespace_ok if {
	count(kubernetes.default_namespace.deny) == 0 with input as {
		"kind": "kubernetes", "file": "deploy.yaml",
		"objects": [{
			"apiVersion": "apps/v1", "kind": "Deployment", "name": "app",
			"manifest": {
				"apiVersion": "apps/v1", "kind": "Deployment",
				"metadata": {"name": "app", "namespace": "payments"},
				"spec": {"template": {"spec": {"containers": [{"name": "app"}]}}},
			},
			"_src": {"file": "deploy.yaml", "line": 1},
		}],
	}
}

test_env_secret_flagged if {
	count(kubernetes.env_secrets.deny) == 1 with input as deployment({"containers": [{
		"name": "app",
		"env": [{"name": "DB_PASSWORD", "value": "FAKE-PASSWORD-00"}],
	}]})
}

test_env_secret_ref_ok if {
	count(kubernetes.env_secrets.deny) == 0 with input as deployment({"containers": [{
		"name": "app",
		"env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "p"}}}],
	}]})
}

test_cronjob_pod_spec_reached if {
	count(kubernetes.privileged.deny) == 1 with input as manifest("CronJob", {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{
		"name": "job",
		"securityContext": {"privileged": true},
	}]}}}}})
}
