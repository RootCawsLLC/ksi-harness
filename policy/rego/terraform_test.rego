# Unit tests for the preventive gates. A policy that has never been shown to fire is not a
# control, so every deny rule here has both a triggering and a non-triggering case.
#
# The inputs below mirror conftest's real HCL parse output, in which each resource body sits
# inside an array. The first version of this suite used hand-written JSON with the body as a bare
# object; all twenty tests passed while the policies matched nothing at all on actual .tf files.
# Fixtures that are not derived from the real parser are a way of testing your assumptions
# instead of your code. `make policy` now runs conftest against policy/terraform as well, so the
# shapes cannot drift apart again silently.
#
#   opa test policy/rego -v

package main

import rego.v1

# Wraps a resource body the way Terraform's JSON configuration shape does.
tf(kind, name, body) := {"resource": {kind: {name: [body]}}}

sg(name, ingress) := tf("aws_security_group", name, {"ingress": ingress})

# ------------------------------------------------------------------- input normalisation

test_reads_the_array_wrapped_configuration_shape if {
	found := resources("aws_security_group") with input as sg("web", [])
	count(found) == 1
	some res in found
	res.name == "web"
	res.label == "aws_security_group.web"
}

# Two blocks of the same type and name is legal Terraform, and both must be seen.
test_reads_repeated_resource_bodies if {
	found := resources("aws_ebs_volume") with input as {"resource": {"aws_ebs_volume": {"scratch": [
		{"encrypted": true},
		{"encrypted": false},
	]}}}
	count(found) == 2
}

test_reads_terraform_plan_output if {
	found := resources("aws_ebs_volume") with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_ebs_volume.scratch",
		"type": "aws_ebs_volume",
		"name": "scratch",
		"values": {"encrypted": false},
	}]}}}
	count(found) == 1
	some res in found
	res.label == "aws_ebs_volume.scratch"
}

# Resources declared inside a module must not be skipped just because they are not at the root.
test_reads_plan_resources_in_child_modules if {
	msgs := deny with input as {"planned_values": {"root_module": {"child_modules": [{"resources": [{
		"address": "module.data.aws_ebs_volume.scratch",
		"type": "aws_ebs_volume",
		"name": "scratch",
		"values": {"encrypted": false},
	}]}]}}}
	count(msgs) == 1
	some msg in msgs
	contains(msg, "module.data.aws_ebs_volume.scratch")
}

# ------------------------------------------------------------------------------ network

test_denies_all_protocols_from_internet if {
	count(deny) == 1 with input as sg("web", [{
		"protocol": "-1",
		"from_port": 0,
		"to_port": 0,
		"cidr_blocks": ["0.0.0.0/0"],
	}])
}

test_denies_ssh_from_internet if {
	count(deny) == 1 with input as sg("bastion", [{
		"protocol": "tcp",
		"from_port": 22,
		"to_port": 22,
		"cidr_blocks": ["0.0.0.0/0"],
	}])
}

wide_range_input := sg("wide", [{
	"protocol": "tcp",
	"from_port": 1,
	"to_port": 10000,
	"cidr_blocks": ["0.0.0.0/0"],
}])

# A range spanning several administrative ports is one misconfigured rule, so it should produce
# one finding that names them all rather than one finding per port.
test_denies_admin_ports_inside_a_wide_range_as_one_finding if {
	count(deny) == 1 with input as wide_range_input
}

test_wide_range_finding_names_every_exposed_admin_port if {
	msgs := deny with input as wide_range_input
	some msg in msgs
	contains(msg, "22")
	contains(msg, "5432")
	contains(msg, "9200")

	# 27017 sits above the range and must not be reported.
	not contains(msg, "27017")
}

test_denies_ipv6_open_admin_port if {
	count(deny) == 1 with input as sg("v6", [{
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"ipv6_cidr_blocks": ["::/0"],
	}])
}

test_allows_https_from_internet if {
	count(deny) == 0 with input as sg("alb", [{
		"protocol": "tcp",
		"from_port": 443,
		"to_port": 443,
		"cidr_blocks": ["0.0.0.0/0"],
	}])
}

test_no_warning_for_declared_public_port if {
	count(warn) == 0 with input as sg("alb", [{
		"protocol": "tcp",
		"from_port": 443,
		"to_port": 443,
		"cidr_blocks": ["0.0.0.0/0"],
	}])
}

test_warns_on_undeclared_public_port if {
	count(warn) == 1 with input as sg("odd", [{
		"protocol": "tcp",
		"from_port": 8080,
		"to_port": 8080,
		"cidr_blocks": ["0.0.0.0/0"],
	}])
}

test_allows_admin_port_from_internal_cidr if {
	count(deny) == 0 with input as sg("db", [{
		"protocol": "tcp",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["10.0.0.0/16"],
	}])
}

# Sourcing from another security group rather than a CIDR is the correct pattern and must not warn.
test_allows_ingress_sourced_from_a_security_group if {
	count(deny) == 0 with input as sg("app", [{
		"protocol": "tcp",
		"from_port": 8443,
		"to_port": 8443,
		"security_groups": ["${aws_security_group.alb.id}"],
	}])
}

test_allows_security_group_with_no_ingress_at_all if {
	count(deny) == 0 with input as tf("aws_security_group", "egress_only", {"name": "egress-only"})
}

# ---------------------------------------------------------------------------- encryption

bucket_only := tf("aws_s3_bucket", "artifacts", {"bucket": "northwind-artifacts"})

bucket_with_encryption := {"resource": {
	"aws_s3_bucket": {"artifacts": [{"bucket": "northwind-artifacts"}]},
	"aws_s3_bucket_server_side_encryption_configuration": {"artifacts": [{"bucket": "${aws_s3_bucket.artifacts.id}"}]},
}}

test_denies_bucket_without_encryption_block if {
	count(deny) == 1 with input as bucket_only
}

test_allows_bucket_with_encryption_block if {
	count(deny) == 0 with input as bucket_with_encryption
}

# The reference must be matched to the right bucket, not to any bucket at all.
test_denies_bucket_whose_encryption_block_targets_a_different_bucket if {
	count(deny) == 1 with input as {"resource": {
		"aws_s3_bucket": {"artifacts": [{"bucket": "northwind-artifacts"}]},
		"aws_s3_bucket_server_side_encryption_configuration": {"other": [{"bucket": "${aws_s3_bucket.other.id}"}]},
	}}
}

test_denies_unencrypted_volume if {
	count(deny) == 1 with input as tf("aws_ebs_volume", "scratch", {"encrypted": false})
}

test_warns_when_volume_encryption_is_unstated if {
	count(warn) == 1 with input as tf("aws_ebs_volume", "scratch", {"size": 20})
}

test_allows_encrypted_volume if {
	count(deny) == 0 with input as tf("aws_ebs_volume", "scratch", {"encrypted": true})
	count(warn) == 0 with input as tf("aws_ebs_volume", "scratch", {"encrypted": true})
}

test_denies_unencrypted_database if {
	count(deny) == 1 with input as tf("aws_db_instance", "main", {"storage_encrypted": false})
}

test_denies_publicly_accessible_database if {
	count(deny) == 1 with input as tf("aws_db_instance", "main", {
		"storage_encrypted": true,
		"publicly_accessible": true,
	})
}

# ------------------------------------------------------------------------ public access

complete_block := {
	"block_public_acls": true,
	"block_public_policy": true,
	"ignore_public_acls": true,
	"restrict_public_buckets": true,
}

test_denies_partial_public_access_block if {
	count(deny) == 1 with input as tf(
		"aws_s3_bucket_public_access_block", "logs",
		object.union(complete_block, {"block_public_policy": false}),
	)
}

test_denies_public_access_block_with_a_missing_field if {
	count(deny) == 1 with input as tf(
		"aws_s3_bucket_public_access_block", "logs",
		object.remove(complete_block, {"restrict_public_buckets"}),
	)
}

test_allows_complete_public_access_block if {
	count(deny) == 0 with input as tf("aws_s3_bucket_public_access_block", "logs", complete_block)
}

# ----------------------------------------------------------------------------- logging

test_denies_trail_without_log_validation if {
	count(deny) == 1 with input as tf("aws_cloudtrail", "org", {
		"enable_log_file_validation": false,
		"is_multi_region_trail": true,
	})
}

test_denies_trail_that_omits_log_validation if {
	count(deny) == 1 with input as tf("aws_cloudtrail", "org", {"is_multi_region_trail": true})
}

test_warns_on_single_region_trail if {
	count(warn) == 1 with input as tf("aws_cloudtrail", "org", {"enable_log_file_validation": true})
}

test_allows_validated_multi_region_trail if {
	count(deny) == 0 with input as tf("aws_cloudtrail", "org", {
		"enable_log_file_validation": true,
		"is_multi_region_trail": true,
	})
	count(warn) == 0 with input as tf("aws_cloudtrail", "org", {
		"enable_log_file_validation": true,
		"is_multi_region_trail": true,
	})
}

# --------------------------------------------------------------------------------- iam

admin_policy := json.marshal({"Statement": [{
	"Effect": "Allow",
	"Action": "*",
	"Resource": "*",
}]})

scoped_policy := json.marshal({"Statement": [{
	"Effect": "Allow",
	"Action": ["s3:GetObject"],
	"Resource": "arn:aws:s3:::northwind-artifacts/*",
}]})

conditioned_policy := json.marshal({"Statement": [{
	"Effect": "Allow",
	"Action": "*",
	"Resource": "*",
	"Condition": {"StringEquals": {"aws:PrincipalTag/break-glass": "true"}},
}]})

# Regression: the string form of Action and Resource. An earlier as_array handled only arrays and
# objects, so this document matched no rule and the gate passed a full administrative grant.
test_denies_unconditional_wildcard_grant_in_string_form if {
	count(deny) == 1 with input as tf("aws_iam_role_policy", "admin", {"policy": admin_policy})
}

test_denies_unconditional_wildcard_grant_in_array_form if {
	doc := json.marshal({"Statement": [{
		"Effect": "Allow",
		"Action": ["*"],
		"Resource": ["*"],
	}]})
	count(deny) == 1 with input as tf("aws_iam_role_policy", "admin", {"policy": doc})
}

# A single statement object rather than an array of them is also valid IAM.
test_denies_wildcard_grant_when_statement_is_a_bare_object if {
	doc := json.marshal({"Statement": {
		"Effect": "Allow",
		"Action": "*",
		"Resource": "*",
	}})
	count(deny) == 1 with input as tf("aws_iam_role_policy", "admin", {"policy": doc})
}

test_denies_wildcard_grant_on_a_standalone_managed_policy if {
	count(deny) == 1 with input as tf("aws_iam_policy", "admin", {"policy": admin_policy})
}

test_allows_scoped_grant if {
	count(deny) == 0 with input as tf("aws_iam_role_policy", "reader", {"policy": scoped_policy})
}

# A wildcard grant bounded by a condition is how just-in-time and break-glass access is
# expressed, so the rule must not fire on it. KSI-IAM-JIT wants the condition, not the absence
# of the grant.
test_allows_wildcard_grant_bounded_by_condition if {
	count(deny) == 0 with input as tf("aws_iam_role_policy", "breakglass", {"policy": conditioned_policy})
}

# The honesty case: a jsonencode() expression is opaque to configuration-only parsing, so the
# gate must report that it could not decide rather than return clean.
test_warns_when_policy_document_is_an_unresolved_expression if {
	msgs := warn with input as tf("aws_iam_role_policy", "admin", {"policy": "${jsonencode({Version = \"2012-10-17\"})}"})
	count(msgs) == 1
	some msg in msgs
	contains(msg, "was not evaluated")
}

test_does_not_deny_what_it_could_not_evaluate if {
	count(deny) == 0 with input as tf("aws_iam_role_policy", "admin", {"policy": "${jsonencode({})}"})
}

# The same grant, resolved by a plan, is decidable and must be denied. This pair is the argument
# for running the gate against plan output rather than configuration.
test_denies_wildcard_grant_resolved_in_plan_output if {
	count(deny) == 1 with input as {"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.admin",
		"type": "aws_iam_role_policy",
		"name": "admin",
		"values": {"policy": admin_policy},
	}]}}}
}
