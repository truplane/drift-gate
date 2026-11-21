"""Native YAML/JSON security & destroy policy engine with optional OPA/Rego support."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from drift_gate.parser import ParsedPlan, ResourceChange

Severity = Literal["critical", "high", "medium", "low"]


class PolicyViolation(BaseModel):
    """Single policy rule failure against a planned resource change."""

    rule_id: str
    severity: Severity
    address: str
    resource_type: str
    message: str
    remediation: str = ""
    engine: str = "native"


class PolicyConfig(BaseModel):
    """Configurable policy settings loaded from policies/*.yaml."""

    max_destroys: int = 3
    enabled_builtin_rules: list[str] = Field(
        default_factory=lambda: [
            "no_public_storage",
            "no_open_admin_ingress",
            "require_encrypted_databases",
            "protect_production_deletes",
        ]
    )
    custom_rules: list[dict[str, Any]] = Field(default_factory=list)


def _extract_tags(attrs: dict[str, Any]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for key in ("tags", "tags_all", "labels"):
        val = attrs.get(key)
        if isinstance(val, dict):
            for k, v in val.items():
                merged[str(k).lower()] = str(v)
    return merged


def _check_public_storage(chg: ResourceChange) -> PolicyViolation | None:
    if chg.action not in ("create", "update", "replace"):
        return None
    attrs = chg.after
    rtype = chg.resource_type

    if rtype in ("aws_s3_bucket", "aws_s3_bucket_acl"):
        acl = str(attrs.get("acl") or "").lower()
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            return PolicyViolation(
                rule_id="no_public_storage",
                severity="critical",
                address=chg.address,
                resource_type=rtype,
                message=f"Storage bucket ACL '{acl}' exposes public access.",
                remediation="Set acl='private' and enforce aws_s3_bucket_public_access_block.",
            )

    if rtype == "aws_s3_bucket_public_access_block":
        disabled = [
            f
            for f in (
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            )
            if attrs.get(f) is False
        ]
        if disabled:
            return PolicyViolation(
                rule_id="no_public_storage",
                severity="critical",
                address=chg.address,
                resource_type=rtype,
                message=f"S3 public access block disables protections: {', '.join(disabled)}.",
                remediation="Set all four public access block flags to true.",
            )

    if rtype in ("google_storage_bucket_iam_binding", "google_storage_bucket_iam_member"):
        members = [str(m) for m in (attrs.get("members") or [])]
        if attrs.get("member"):
            members.append(str(attrs["member"]))
        if any(m in ("allUsers", "allAuthenticatedUsers") for m in members):
            return PolicyViolation(
                rule_id="no_public_storage",
                severity="critical",
                address=chg.address,
                resource_type=rtype,
                message="GCS bucket IAM grants public access to allUsers/allAuthenticatedUsers.",
                remediation="Restrict bucket IAM bindings to specific principals.",
            )

    if rtype == "azurerm_storage_account" and attrs.get("allow_nested_items_to_be_public") is True:
        return PolicyViolation(
            rule_id="no_public_storage",
            severity="critical",
            address=chg.address,
            resource_type=rtype,
            message="Azure storage account permits public blob/container access.",
            remediation="Set allow_nested_items_to_be_public=false.",
        )

    if rtype == "azurerm_storage_container" and str(attrs.get("container_access_type") or "").lower() in (
        "blob",
        "container",
    ):
        return PolicyViolation(
            rule_id="no_public_storage",
            severity="critical",
            address=chg.address,
            resource_type=rtype,
            message="Azure storage container enables anonymous public read access.",
            remediation="Set container_access_type='private'.",
        )

    return None


def _rule_opens_admin_port(rule: dict[str, Any]) -> list[int]:
    cidrs = [str(c) for c in (rule.get("cidr_blocks") or [])]
    ipv6 = [str(c) for c in (rule.get("ipv6_cidr_blocks") or [])]
    if rule.get("cidr_ipv4"):
        cidrs.append(str(rule["cidr_ipv4"]))
    if rule.get("cidr_ipv6"):
        ipv6.append(str(rule["cidr_ipv6"]))
    if rule.get("source_ranges") and isinstance(rule["source_ranges"], list):
        cidrs.extend(str(c) for c in rule["source_ranges"])

    is_open = "0.0.0.0/0" in cidrs or "::/0" in ipv6
    if not is_open:
        return []

    proto = str(rule.get("protocol") or rule.get("ip_protocol") or "tcp").lower()
    if proto in ("-1", "all"):
        return [22, 3389]

    from_port = rule.get("from_port")
    to_port = rule.get("to_port")
    if from_port is None and to_port is None:
        return []
    fp = int(from_port if from_port is not None else to_port)
    tp = int(to_port if to_port is not None else from_port)
    if fp == 0 and tp == 0:
        return [22, 3389]
    exposed = [p for p in (22, 3389) if fp <= p <= tp]
    return exposed


def _check_open_admin_ingress(chg: ResourceChange) -> PolicyViolation | None:
    if chg.action not in ("create", "update", "replace"):
        return None
    attrs = chg.after
    rtype = chg.resource_type

    if rtype == "aws_security_group":
        for ing in attrs.get("ingress") or []:
            if isinstance(ing, dict):
                exposed = _rule_opens_admin_port(ing)
                if exposed:
                    return PolicyViolation(
                        rule_id="no_open_admin_ingress",
                        severity="critical",
                        address=chg.address,
                        resource_type=rtype,
                        message=f"Security group exposes port(s) {exposed} to 0.0.0.0/0 or ::/0.",
                        remediation="Restrict SSH (22) and RDP (3389) ingress to VPN/bastion CIDRs.",
                    )

    if rtype in ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
        rule_type = str(attrs.get("type") or "ingress").lower()
        if rule_type == "ingress" or rtype == "aws_vpc_security_group_ingress_rule":
            exposed = _rule_opens_admin_port(attrs)
            if exposed:
                return PolicyViolation(
                    rule_id="no_open_admin_ingress",
                    severity="critical",
                    address=chg.address,
                    resource_type=rtype,
                    message=f"Ingress rule exposes admin port(s) {exposed} to 0.0.0.0/0 or ::/0.",
                    remediation="Restrict ingress CIDRs to trusted internal ranges.",
                )

    if rtype == "google_compute_firewall":
        ranges = [str(r) for r in (attrs.get("source_ranges") or [])]
        if "0.0.0.0/0" in ranges:
            for allow in attrs.get("allow") or []:
                ports = [str(p) for p in (allow.get("ports") or [])]
                if not ports or "22" in ports or "3389" in ports:
                    return PolicyViolation(
                        rule_id="no_open_admin_ingress",
                        severity="critical",
                        address=chg.address,
                        resource_type=rtype,
                        message="GCP firewall allows 0.0.0.0/0 access to admin ports (22/3389).",
                        remediation="Remove 0.0.0.0/0 from source_ranges.",
                    )
    return None


def _check_encrypted_databases(chg: ResourceChange) -> PolicyViolation | None:
    if chg.action not in ("create", "update", "replace"):
        return None
    attrs = chg.after
    rtype = chg.resource_type

    if rtype in ("aws_db_instance", "aws_rds_cluster"):
        if attrs.get("storage_encrypted") is not True:
            return PolicyViolation(
                rule_id="require_encrypted_databases",
                severity="high",
                address=chg.address,
                resource_type=rtype,
                message=f"Database '{chg.address}' does not have storage_encrypted=true.",
                remediation="Enable storage_encrypted=true (with kms_key_id).",
            )
    if rtype == "google_sql_database_instance":
        settings = attrs.get("settings")
        if isinstance(settings, list) and settings:
            settings = settings[0]
        if isinstance(settings, dict) and settings.get("disk_encryption_configuration") is None:
            # Allow default Google-managed encryption unless explicitly disabled via flag
            if attrs.get("encryption_enabled") is False:
                return PolicyViolation(
                    rule_id="require_encrypted_databases",
                    severity="high",
                    address=chg.address,
                    resource_type=rtype,
                    message=f"Cloud SQL instance '{chg.address}' disables encryption.",
                    remediation="Enable disk encryption configuration.",
                )
    return None


def _check_production_deletes(chg: ResourceChange) -> PolicyViolation | None:
    if chg.action not in ("delete", "replace"):
        return None
    tags = _extract_tags(chg.before) or _extract_tags(chg.after)
    env = tags.get("environment") or tags.get("env") or ""
    is_prod = env.lower() in ("prod", "production")
    if not is_prod and not env:
        is_prod = "prod" in chg.address.lower()
    if not is_prod:
        return None

    override = tags.get("drift_gate_override", "").lower() == "true"
    if override:
        return None

    return PolicyViolation(
        rule_id="protect_production_deletes",
        severity="critical",
        address=chg.address,
        resource_type=chg.resource_type,
        message=(
            f"Destructive {chg.action} on production resource '{chg.address}' "
            "blocked without tag drift_gate_override='true'."
        ),
        remediation="Add tag drift_gate_override='true' with approval or avoid destructive change.",
    )


_BUILTIN_EVALUATORS = {
    "no_public_storage": _check_public_storage,
    "no_open_admin_ingress": _check_open_admin_ingress,
    "require_encrypted_databases": _check_encrypted_databases,
    "protect_production_deletes": _check_production_deletes,
}


def load_policy_config(policies_dir: Path | str | None) -> tuple[PolicyConfig, list[Path]]:
    """Load YAML policy configurations and discover .rego files in policies_dir."""
    if policies_dir is None:
        return PolicyConfig(), []
    p = Path(policies_dir)
    if p.is_file():
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return PolicyConfig.model_validate(raw), []

    cfg_data: dict[str, Any] = {}
    custom_rules: list[dict[str, Any]] = []
    if p.is_dir():
        for yaml_file in sorted(list(p.glob("*.yaml")) + list(p.glob("*.yml"))):
            loaded = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                if "custom_rules" in loaded and isinstance(loaded["custom_rules"], list):
                    custom_rules.extend(loaded["custom_rules"])
                cfg_data.update({k: v for k, v in loaded.items() if k != "custom_rules"})
        rego_files = sorted(p.glob("*.rego"))
    else:
        rego_files = []

    if custom_rules:
        cfg_data["custom_rules"] = custom_rules
    return PolicyConfig.model_validate(cfg_data), rego_files


def _evaluate_custom_rule(rule: dict[str, Any], chg: ResourceChange) -> PolicyViolation | None:
    target_types = rule.get("resource_types") or []
    if target_types and chg.resource_type not in target_types:
        return None
    allowed_actions = rule.get("actions") or ["create", "update", "replace"]
    if chg.action not in allowed_actions:
        return None

    attrs = chg.before if chg.action == "delete" else chg.after
    attr_key = str(rule.get("attribute") or "")
    forbidden = rule.get("forbidden_values")
    required = rule.get("required_value")

    if attr_key:
        actual = attrs.get(attr_key)
        if forbidden is not None and actual in forbidden:
            return PolicyViolation(
                rule_id=str(rule.get("id") or "custom_rule"),
                severity=str(rule.get("severity") or "high"),  # type: ignore[arg-type]
                address=chg.address,
                resource_type=chg.resource_type,
                message=str(rule.get("message") or f"Attribute {attr_key}={actual} is forbidden."),
                remediation=str(rule.get("remediation") or ""),
                engine="native-yaml",
            )
        if required is not None and actual != required:
            return PolicyViolation(
                rule_id=str(rule.get("id") or "custom_rule"),
                severity=str(rule.get("severity") or "high"),  # type: ignore[arg-type]
                address=chg.address,
                resource_type=chg.resource_type,
                message=str(
                    rule.get("message")
                    or f"Attribute {attr_key} must equal {required!r} (got {actual!r})."
                ),
                remediation=str(rule.get("remediation") or ""),
                engine="native-yaml",
            )
    return None


def _run_opa_if_available(plan: ParsedPlan, rego_files: list[Path]) -> list[PolicyViolation]:
    """Invoke `opa eval` when the OPA binary is installed and .rego policies exist."""
    opa_bin = shutil.which("opa")
    if not opa_bin or not rego_files:
        return []
    violations: list[PolicyViolation] = []
    cmd = [opa_bin, "eval", "--format", "json", "--stdin-input"]
    for rf in rego_files:
        cmd.extend(["-d", str(rf)])
    cmd.append("data.drift_gate.deny")
    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps(plan.raw),
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0:
            return []
        out = json.loads(proc.stdout or "{}")
        for result in out.get("result", []):
            for expr in result.get("expressions", []):
                val = expr.get("value")
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            violations.append(
                                PolicyViolation(
                                    rule_id=str(item.get("rule_id") or "opa_deny"),
                                    severity=str(item.get("severity") or "high"),  # type: ignore[arg-type]
                                    address=str(item.get("address") or "plan"),
                                    resource_type=str(item.get("resource_type") or "unknown"),
                                    message=str(item.get("message") or "OPA policy denied change."),
                                    engine="opa",
                                )
                            )
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []
    return violations


def evaluate_policies(
    plan: ParsedPlan,
    policies_dir: Path | str | None = None,
) -> tuple[list[PolicyViolation], PolicyConfig, list[str]]:
    """Evaluate all native and optional OPA policies against a ParsedPlan."""
    cfg, rego_files = load_policy_config(policies_dir)
    violations: list[PolicyViolation] = []
    engines_used = ["native"]

    for chg in plan.changes:
        for rule_id in cfg.enabled_builtin_rules:
            fn = _BUILTIN_EVALUATORS.get(rule_id)
            if fn is not None:
                hit = fn(chg)
                if hit is not None:
                    violations.append(hit)
        for custom in cfg.custom_rules:
            hit = _evaluate_custom_rule(custom, chg)
            if hit is not None:
                violations.append(hit)

    opa_hits = _run_opa_if_available(plan, rego_files)
    if opa_hits:
        engines_used.append("opa")
        existing_pairs = {(v.rule_id, v.address) for v in violations}
        for hit in opa_hits:
            if (hit.rule_id, hit.address) not in existing_pairs:
                violations.append(hit)

    return violations, cfg, engines_used
