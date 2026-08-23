package boundary.docker_test

import data.boundary.docker

df(instructions) := {"kind": "docker", "file": "Dockerfile", "instructions": instructions, "stages": []}

inst(cmd, value, line) := {"cmd": cmd, "value": value, "line": line}

test_no_user_flagged if {
	count(docker.root_user.deny) == 1 with input as df([inst("FROM", "alpine:3.21", 1)])
}

test_root_user_flagged if {
	count(docker.root_user.deny) == 1 with input as df([
		inst("FROM", "alpine:3.21", 1),
		inst("USER", "root", 2),
	])
}

test_nonroot_user_ok if {
	count(docker.root_user.deny) == 0 with input as df([
		inst("FROM", "alpine:3.21", 1),
		inst("USER", "app", 2),
	])
}

test_build_stage_user_ignored if {
	count(docker.root_user.deny) == 1 with input as df([
		inst("FROM", "golang:1.23 AS build", 1),
		inst("USER", "app", 2),
		inst("FROM", "alpine:3.21", 3),
	])
}

test_latest_tag_flagged if {
	count(docker.image_tag.deny) == 1 with input as df([inst("FROM", "node:latest", 1)])
}

test_untagged_flagged if {
	count(docker.image_tag.deny) == 1 with input as df([inst("FROM", "node", 1)])
}

test_pinned_tag_ok if {
	count(docker.image_tag.deny) == 0 with input as df([inst("FROM", "node:22.12-alpine", 1)])
}

test_stage_reference_ok if {
	count(docker.image_tag.deny) == 0 with input as {
		"kind": "docker", "file": "Dockerfile", "stages": ["build"],
		"instructions": [inst("FROM", "build", 5)],
	}
}

test_env_secret_flagged if {
	count(docker.env_secrets.deny) == 1 with input as df([inst("ENV", "API_KEY=FAKE-KEY-12345678", 2)])
}

test_env_reference_ok if {
	count(docker.env_secrets.deny) == 0 with input as df([inst("ENV", "API_KEY=$RUNTIME_KEY", 2)])
}

test_curl_pipe_sh_flagged if {
	count(docker.curl_pipe_shell.deny) == 1 with input as df([inst("RUN", "curl -s https://x.sh | sh", 3)])
}

test_plain_curl_ok if {
	count(docker.curl_pipe_shell.deny) == 0 with input as df([inst("RUN", "curl -fsSLo /tmp/t.sh https://x.sh", 3)])
}

test_add_flagged if {
	count(docker.add_instruction.deny) == 1 with input as df([inst("ADD", "app.tar.gz /opt/", 4)])
}

test_add_with_checksum_ok if {
	count(docker.add_instruction.deny) == 0 with input as df([inst("ADD", "--checksum=sha256:abc https://x/f /opt/", 4)])
}

test_missing_healthcheck_flagged if {
	count(docker.healthcheck.deny) == 1 with input as df([inst("EXPOSE", "8080", 5)])
}

test_healthcheck_present_ok if {
	count(docker.healthcheck.deny) == 0 with input as df([
		inst("EXPOSE", "8080", 5),
		inst("HEALTHCHECK", "CMD curl -f http://localhost/health", 6),
	])
}

test_expose_ssh_flagged if {
	count(docker.expose_ssh.deny) == 1 with input as df([inst("EXPOSE", "22", 5)])
}

test_expose_web_ok if {
	count(docker.expose_ssh.deny) == 0 with input as df([inst("EXPOSE", "8080 8443", 5)])
}

test_chmod_777_flagged if {
	count(docker.world_writable.deny) == 1 with input as df([inst("RUN", "chmod -R 777 /app", 6)])
}

test_chmod_755_ok if {
	count(docker.world_writable.deny) == 0 with input as df([inst("RUN", "chmod 755 /app", 6)])
}

test_missing_oci_labels_flagged if {
	count(docker.oci_labels.deny) == 1 with input as df([inst("FROM", "alpine:3.21", 1)])
}

test_complete_oci_labels_ok if {
	count(docker.oci_labels.deny) == 0 with input as df([inst(
		"LABEL",
		`org.opencontainers.image.source="https://example.com/app" org.opencontainers.image.version="1.2.3" org.opencontainers.image.description="Example app"`,
		2,
	)])
}
