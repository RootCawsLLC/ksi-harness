# Preventive policy gates, keyed to the same Key Security Indicators the collectors evidence.
#
# The pairing is the point. Every rule here names the indicator it enforces, and that indicator
# also has a detective check in src/collectors — so the same claim is enforced before merge and
# verified after deploy. Neither alone is enough: a gate cannot see a change made outside the
# pipeline, and a collector cannot stop the change from shipping.
#
# Two input shapes are supported, because they answer different questions:
#
#   configuration  conftest's HCL parse of *.tf. Cheap, runs on a pull request with no cloud
#                  credentials, but attribute values that come from variables, locals, or module
#                  outputs arrive as unresolved "${...}" strings and cannot be judged.
#   plan           `terraform show -json tfplan`. Values are resolved, so far more is decidable,
#                  but it needs an init and a provider.
#
# Rules that can only be evaluated against resolved values say so out loud rather than passing
# quietly — see unresolved_expression below. That distinction is why the routes in
# src/routes/routes.yaml credit this layer as `partial` and never as sufficient on its own.
#
#   opa test policy/rego
#   conftest test --policy policy/rego policy/terraform/compliant
#   terraform show -json tfplan | conftest test --policy policy/rego -

package main

import rego.v1

# Ports a public-facing service is expected to expose. Anything else reachable from the internet
# is a finding rather than a design choice.
public_ports := {80, 443}

admin_ports := {22, 3389, 3306, 5432, 6379, 9200, 27017}

# ---------------------------------------------------------------------- input normalisation

# Terraform's JSON configuration shape nests each resource body in an array, since the same
# type/name pair can legally appear more than once. An earlier version of this file read
# input.resource[kind][name] as the body directly; every positive-form rule then silently matched
# nothing while the one negative-form rule kept firing, so the suite looked healthy. Unit tests
# built from hand-written JSON did not catch it. The tests now mirror this shape exactly.
config_resources(kind) := [{"name": name, "body": body, "label": sprintf("%s.%s", [kind, name])} |
	some name, raw in object.get(input, ["resource", kind], {})
	some body in as_array(raw)
]

# `terraform show -json` output. walk reaches resources in nested child modules as well as the
# root, which a fixed path would miss.
plan_resources(kind) := [{"name": res.name, "body": res.values, "label": res.address} |
	walk(object.get(input, ["planned_values", "root_module"], {}), [_, res])
	is_object(res)
	res.type == kind
	res.address
	res.values
]

resources(kind) := array.concat(config_resources(kind), plan_resources(kind))

# True when the value is a Terraform interpolation that configuration-only parsing cannot resolve.
unresolved_expression(value) if contains(sprintf("%v", [value]), "${")

# A resource attribute reference such as "${aws_s3_bucket.artifacts.id}", or a resolved value that
# equals the target's own name or bucket attribute.
references(value, res) if contains(sprintf("%v", [value]), sprintf(".%s.", [res.name]))

references(value, res) if sprintf("%v", [value]) == sprintf("%v", [res.name])

references(value, res) if sprintf("%v", [value]) == sprintf("%v", [res.body.bucket])

# ---------------------------------------------------------------- KSI-CNA-RNT, KSI-CNA-MAT

open_cidr(block) if "0.0.0.0/0" in block.cidr_blocks

open_cidr(block) if "::/0" in block.ipv6_cidr_blocks

port_range_covers(block, port) if {
	block.from_port <= port
	block.to_port >= port
}

# All protocols means every port, including the administrative ones.
all_protocols(block) if block.protocol == "-1"

ingress_blocks(res) := [block |
	some raw in as_array(object.get(res, ["body", "ingress"], []))
	block := raw
]

deny contains msg if {
	some res in resources("aws_security_group")
	some block in ingress_blocks(res)
	open_cidr(block)
	all_protocols(block)
	msg := sprintf(
		"KSI-CNA-RNT / KSI-CNA-MAT: %s allows all protocols from the internet. Restrict the protocol and port range, or scope the source to a CIDR inside the boundary.",
		[res.label],
	)
}

exposed_admin_ports(block) := {port |
	some port in admin_ports
	port_range_covers(block, port)
}

# One finding per offending ingress rule, listing every administrative port it exposes. Emitting
# a separate message per port turns a single misconfigured rule into six lines of output, which
# trains reviewers to skim.
deny contains msg if {
	some res in resources("aws_security_group")
	some block in ingress_blocks(res)
	open_cidr(block)
	not all_protocols(block)
	ports := exposed_admin_ports(block)
	count(ports) > 0
	msg := sprintf(
		"KSI-CNA-RNT / KSI-CNA-MAT: %s exposes administrative port(s) %v to the internet via the range %v-%v. Front them with SSM Session Manager or a private endpoint.",
		[res.label, sort(ports), block.from_port, block.to_port],
	)
}

# A rule opening the internet to something other than the declared public service ports is worth
# flagging even when it is not a known administrative port: the boundary's public surface should
# be enumerable, and an unrecognised open port is by definition not.
warn contains msg if {
	some res in resources("aws_security_group")
	some block in ingress_blocks(res)
	open_cidr(block)
	not all_protocols(block)
	count(exposed_admin_ports(block)) == 0
	not declared_public(block)
	msg := sprintf(
		"KSI-CNA-RNT: %s opens %v-%v to the internet, which is outside the declared public service ports %v. Confirm this belongs in the public surface.",
		[res.label, block.from_port, block.to_port, sort(public_ports)],
	)
}

declared_public(block) if {
	block.from_port == block.to_port
	block.from_port in public_ports
}

# --------------------------------------------------------------------------- KSI-SVC-SIN

deny contains msg if {
	some res in resources("aws_s3_bucket")
	not encryption_configured(res)
	msg := sprintf(
		"KSI-SVC-SIN: %s has no aws_s3_bucket_server_side_encryption_configuration. Encryption at rest is not optional in a federal boundary.",
		[res.label],
	)
}

encryption_configured(bucket) if {
	some cfg in resources("aws_s3_bucket_server_side_encryption_configuration")
	references(cfg.body.bucket, bucket)
}

deny contains msg if {
	some res in resources("aws_ebs_volume")
	res.body.encrypted == false
	msg := sprintf("KSI-SVC-SIN: %s sets encrypted = false.", [res.label])
}

# Absent means false for aws_ebs_volume unless the account default is on, and the account default
# is not visible from Terraform. The collector aws.data.encryption-at-rest checks that default
# directly; here it is a warning so a pull request is not blocked on something unknowable at
# this layer.
warn contains msg if {
	some res in resources("aws_ebs_volume")
	not has_key(res.body, "encrypted")
	msg := sprintf(
		"KSI-SVC-SIN: %s does not set encrypted, so it inherits the account default, which this layer cannot see. Set it explicitly.",
		[res.label],
	)
}

deny contains msg if {
	some res in resources("aws_db_instance")
	res.body.storage_encrypted == false
	msg := sprintf("KSI-SVC-SIN: %s sets storage_encrypted = false.", [res.label])
}

deny contains msg if {
	some res in resources("aws_db_instance")
	res.body.publicly_accessible == true
	msg := sprintf(
		"KSI-CNA-RNT: %s sets publicly_accessible = true, placing a database on a public endpoint.",
		[res.label],
	)
}

# --------------------------------------------------------------------------- KSI-MLA-ALA

public_access_block_fields := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

deny contains msg if {
	some res in resources("aws_s3_bucket_public_access_block")
	some field in public_access_block_fields
	res.body[field] == false
	msg := sprintf(
		"KSI-MLA-ALA: %s sets %s = false. All four must be true; a partial block is not a block.",
		[res.label, field],
	)
}

deny contains msg if {
	some res in resources("aws_s3_bucket_public_access_block")
	some field in public_access_block_fields
	not has_key(res.body, field)
	msg := sprintf(
		"KSI-MLA-ALA: %s omits %s, which defaults to permissive. State all four explicitly.",
		[res.label, field],
	)
}

# ---------------------------------------------------------------- KSI-MLA-LET, KSI-MLA-OSM

deny contains msg if {
	some res in resources("aws_cloudtrail")
	res.body.enable_log_file_validation == false
	msg := sprintf(
		"KSI-MLA-OSM: %s disables log file validation, which is what makes the audit record tamper-evident.",
		[res.label],
	)
}

deny contains msg if {
	some res in resources("aws_cloudtrail")
	not has_key(res.body, "enable_log_file_validation")
	msg := sprintf(
		"KSI-MLA-OSM: %s does not enable log file validation, which defaults to off.",
		[res.label],
	)
}

warn contains msg if {
	some res in resources("aws_cloudtrail")
	not res.body.is_multi_region_trail
	msg := sprintf(
		"KSI-MLA-LET: %s is not multi-region, so activity in unlisted regions is unlogged.",
		[res.label],
	)
}

# ---------------------------------------------------------------- KSI-IAM-ELP, KSI-IAM-JIT

policy_bearing_types := ["aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy", "aws_iam_group_policy"]

policy_documents contains doc if {
	some kind in policy_bearing_types
	some res in resources(kind)
	doc := {"label": res.label, "policy": res.body.policy}
}

deny contains msg if {
	some doc in policy_documents
	not unresolved_expression(doc.policy)
	some stmt in policy_statements(doc.policy)
	wildcard_allow(stmt)
	msg := sprintf(
		"KSI-IAM-ELP / KSI-IAM-JIT: %s allows Action \"*\" on Resource \"*\" with no condition. Scope the actions, or add a condition that bounds when the grant applies.",
		[doc.label],
	)
}

# jsonencode(...) in a .tf file arrives as an unevaluated template string, so the document cannot
# be inspected from configuration alone. Reporting that honestly is the whole point: a silent pass
# here would be indistinguishable from a clean result, and this is precisely where a wildcard
# administrative grant would hide.
warn contains msg if {
	some doc in policy_documents
	unresolved_expression(doc.policy)
	msg := sprintf(
		"KSI-IAM-ELP: the policy document on %s is built by an unresolved expression and was not evaluated. Run this gate against `terraform show -json` plan output to decide it.",
		[doc.label],
	)
}

policy_statements(raw) := stmts if {
	doc := json.unmarshal(raw)
	stmts := as_array(doc.Statement)
}

wildcard_allow(stmt) if {
	stmt.Effect == "Allow"
	not stmt.Condition
	"*" in as_array(stmt.Action)
	"*" in as_array(stmt.Resource)
}

# ------------------------------------------------------------------------------- helpers

# IAM policy documents let Action and Resource be either a string or an array, and Statement
# either an object or an array. Normalising both shapes matters: an earlier version handled only
# arrays and objects, so the string form `"Action": "*"` matched nothing and the gate reported
# clean on a full administrative grant.
as_array(value) := value if is_array(value)

as_array(value) := [value] if not is_array(value)

has_key(obj, key) if _ = obj[key]
