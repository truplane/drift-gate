"""Tests for Drift Gate plan parsing, policies, blast-radius, Markdown, and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from drift_gate.blast_radius import evaluate_plan, render_markdown
from drift_gate.cli import app as cli_app
from drift_gate.parser import parse_plan_dict, parse_plan_file
from drift_gate.policy import evaluate_policies

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
POLICIES = ROOT / "policies"


def test_clean_plan_exits_zero() -> None:
    runner = CliRunner()
    res = runner.invoke(
        cli_app,
        [
            "evaluate",
            "--plan",
            str(EXAMPLES / "plan_clean.json"),
            "--policies",
            str(POLICIES),
            "--format",
            "markdown",
        ],
    )
    assert res.exit_code == 0, res.output
    assert "**PASS**" in res.stdout
    assert "exit `0`" in res.stdout


def test_policy_violations_exit_two_and_cover_all_rules() -> None:
    runner = CliRunner()
    res = runner.invoke(
        cli_app,
        [
            "evaluate",
            "--plan",
            str(EXAMPLES / "plan_violation.json"),
            "--policies",
            str(POLICIES),
            "--format",
            "json",
        ],
    )
    assert res.exit_code == 2
    payload = json.loads(res.stdout)
    assert payload["status"] == "POLICY_VIOLATION"
    rules_hit = {v["rule_id"] for v in payload["violations"]}
    assert {
        "no_public_storage",
        "no_open_admin_ingress",
        "require_encrypted_databases",
        "protect_production_deletes",
    } <= rules_hit
    assert "drift_gate_policy_violations_total" in payload["prometheus_metrics"]


def test_drift_plan_exits_three_and_generates_markdown() -> None:
    runner = CliRunner()
    res = runner.invoke(
        cli_app,
        [
            "evaluate",
            "--plan",
            str(EXAMPLES / "plan_drift.json"),
            "--policies",
            str(POLICIES),
            "--format",
            "markdown",
        ],
    )
    assert res.exit_code == 3
    assert "DRIFT_DETECTED" in res.stdout
    assert "aws_security_group.web_edge" in res.stdout
    assert "Out-of-Band Drift" in res.stdout


def test_prod_delete_override_and_blast_radius_gate() -> None:
    plan_dict = {
        "resource_changes": [
            {
                "address": f"aws_instance.worker_{i}",
                "type": "aws_instance",
                "name": f"worker_{i}",
                "change": {
                    "actions": ["delete"],
                    "before": {
                        "tags": {
                            "environment": "prod",
                            "drift_gate_override": "true",
                        }
                    },
                    "after": None,
                },
            }
            for i in range(4)
        ],
        "resource_drift": [],
    }
    parsed = parse_plan_dict(plan_dict)
    violations, _, engines = evaluate_policies(parsed, POLICIES)
    # Prod delete override tag suppresses protect_production_deletes
    assert not any(v.rule_id == "protect_production_deletes" for v in violations)

    # Yet destroying 4 resources exceeds max_destroys=2
    report = evaluate_plan(parsed, violations, max_destroys=2, engines_used=engines)
    assert report.exit_code == 2
    assert report.blast_radius_exceeded is True
    assert any(v.rule_id == "blast_radius_max_destroys" for v in report.violations)
    md = render_markdown(report)
    assert "blast_radius_max_destroys" in md


def test_metrics_file_written(tmp_path: Path) -> None:
    metrics_file = tmp_path / "drift_gate.prom"
    parsed = parse_plan_file(EXAMPLES / "plan_clean.json")
    violations, cfg, engines = evaluate_policies(parsed, POLICIES)
    report = evaluate_plan(parsed, violations, max_destroys=cfg.max_destroys, engines_used=engines)
    assert report.exit_code == 0

    runner = CliRunner()
    res = runner.invoke(
        cli_app,
        [
            "evaluate",
            "--plan",
            str(EXAMPLES / "plan_clean.json"),
            "--policies",
            str(POLICIES),
            "--metrics-out",
            str(metrics_file),
        ],
    )
    assert res.exit_code == 0
    assert metrics_file.is_file()
    prom_text = metrics_file.read_text(encoding="utf-8")
    assert "drift_gate_blast_radius_score" in prom_text


def test_multicloud_gcp_azure_and_custom_rules() -> None:
    plan_dict = {
        "resource_changes": [
            {
                "address": "google_storage_bucket_iam_binding.public_logs",
                "type": "google_storage_bucket_iam_binding",
                "name": "public_logs",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"bucket": "logs", "role": "roles/storage.objectViewer", "members": ["allUsers"]},
                },
            },
            {
                "address": "google_compute_firewall.allow_ssh",
                "type": "google_compute_firewall",
                "name": "allow_ssh",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "source_ranges": ["0.0.0.0/0"],
                        "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    },
                },
            },
            {
                "address": "azurerm_storage_container.public_blob",
                "type": "azurerm_storage_container",
                "name": "public_blob",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"name": "exports", "container_access_type": "blob"},
                },
            },
            {
                "address": "aws_s3_bucket_public_access_block.disabled_pab",
                "type": "aws_s3_bucket_public_access_block",
                "name": "disabled_pab",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "block_public_acls": False,
                        "block_public_policy": True,
                        "ignore_public_acls": True,
                        "restrict_public_buckets": True,
                    },
                },
            },
        ],
        "resource_drift": [],
    }
    parsed = parse_plan_dict(plan_dict)
    violations, cfg, engines = evaluate_policies(parsed, POLICIES)
    report = evaluate_plan(parsed, violations, max_destroys=cfg.max_destroys, engines_used=engines)
    assert report.exit_code == 2
    by_addr = {v.address: v.rule_id for v in report.violations}
    assert by_addr["google_storage_bucket_iam_binding.public_logs"] == "no_public_storage"
    assert by_addr["google_compute_firewall.allow_ssh"] == "no_open_admin_ingress"
    assert by_addr["azurerm_storage_container.public_blob"] == "no_public_storage"
    assert by_addr["aws_s3_bucket_public_access_block.disabled_pab"] == "no_public_storage"


def test_v3_sku_aware_pricing_truplane_budget_gate_and_watch(tmp_path: Path) -> None:
    from drift_gate.pricing_client import SKUPricingResolver

    sku_plan = tmp_path / "sku_plan.json"
    sku_plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_db_instance.heavy_analytics",
                        "type": "aws_db_instance",
                        "name": "heavy_analytics",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {
                                "instance_class": "db.r6g.4xlarge",
                                "storage_encrypted": True,
                            },
                        },
                    }
                ],
                "resource_drift": [],
            }
        ),
        encoding="utf-8",
    )

    truplane_cfg = tmp_path / "truplane.yaml"
    truplane_cfg.write_text(
        """
governance:
  max_monthly_spend_delta_usd: 500.0
drift_gate:
  max_destroys: 3
""",
        encoding="utf-8",
    )

    resolver = SKUPricingResolver()
    assert resolver.monthly_cost("aws_db_instance", "db.r6g.4xlarge") == 1512.0
    assert resolver.monthly_cost("aws_db_instance", "db.t3.micro") == 14.5

    runner = CliRunner()
    res = runner.invoke(
        cli_app,
        [
            "evaluate",
            "--plan",
            str(sku_plan),
            "--policies",
            str(POLICIES),
            "--config",
            str(truplane_cfg),
            "--format",
            "json",
        ],
    )
    assert res.exit_code == 2
    payload = json.loads(res.stdout)
    assert payload["estimated_monthly_cost_delta_usd"] == 1512.0
    assert any(v["rule_id"] == "governance_spend_delta_exceeded" for v in payload["violations"])

    watch_res = runner.invoke(
        cli_app,
        [
            "watch",
            "--plan",
            str(EXAMPLES / "plan_drift.json"),
            "--policies",
            str(POLICIES),
            "--once",
        ],
    )
    assert watch_res.exit_code == 3
    assert "DRIFT_DETECTED" in watch_res.stdout


