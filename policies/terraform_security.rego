package drift_gate

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Deny public S3 buckets
deny contains violation if {
    some rc in input.resource_changes
    rc.type in {"aws_s3_bucket", "aws_s3_bucket_acl"}
    rc.change.after.acl in {"public-read", "public-read-write", "authenticated-read"}
    violation := {
        "rule_id": "opa_no_public_storage",
        "severity": "critical",
        "address": rc.address,
        "resource_type": rc.type,
        "message": sprintf("Public S3 ACL '%s' is denied by OPA policy.", [rc.change.after.acl]),
    }
}

# Deny 0.0.0.0/0 SSH/RDP security group ingress
deny contains violation if {
    some rc in input.resource_changes
    rc.type == "aws_security_group"
    some rule in rc.change.after.ingress
    "0.0.0.0/0" in rule.cidr_blocks
    rule.from_port <= 22
    rule.to_port >= 22
    violation := {
        "rule_id": "opa_no_open_ssh",
        "severity": "critical",
        "address": rc.address,
        "resource_type": rc.type,
        "message": "Security group opens SSH port 22 to 0.0.0.0/0.",
    }
}

# Deny unencrypted RDS databases
deny contains violation if {
    some rc in input.resource_changes
    rc.type in {"aws_db_instance", "aws_rds_cluster"}
    rc.change.after.storage_encrypted != true
    violation := {
        "rule_id": "opa_require_encrypted_db",
        "severity": "high",
        "address": rc.address,
        "resource_type": rc.type,
        "message": "RDS database must enable storage_encrypted=true.",
    }
}
