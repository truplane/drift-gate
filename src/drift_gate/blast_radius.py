"""Blast-radius analysis, cost-delta heuristics, Markdown PR report, and Prometheus metrics."""

from __future__ import annotations

from pydantic import BaseModel, Field

from drift_gate.parser import ParsedPlan
from drift_gate.policy import PolicyViolation

_MONTHLY_COST_HEURISTIC_USD: dict[str, float] = {
    "aws_db_instance": 145.0,
    "aws_rds_cluster": 290.0,
    "aws_instance": 68.0,
    "aws_eks_cluster": 73.0,
    "aws_nat_gateway": 33.0,
    "aws_lb": 22.0,
    "aws_s3_bucket": 5.0,
    "google_sql_database_instance": 140.0,
    "azurerm_mssql_server": 150.0,
}

_ACTION_WEIGHT: dict[str, int] = {
    "create": 1,
    "update": 2,
    "replace": 5,
    "delete": 6,
}


class EvaluationReport(BaseModel):
    """Complete evaluation outcome across drift, policy, and blast-radius gates."""

    exit_code: int
    status: str
    engines_used: list[str] = Field(default_factory=list)
    action_counts: dict[str, int]
    destroys_total: int
    max_destroys_allowed: int
    blast_radius_exceeded: bool
    blast_radius_score: int
    estimated_monthly_cost_delta_usd: float
    drift_count: int
    drifts: list[dict[str, object]] = Field(default_factory=list)
    violation_count: int
    violations: list[PolicyViolation] = Field(default_factory=list)
    prometheus_metrics: str = ""


def _estimate_cost_delta(plan: ParsedPlan) -> float:
    delta = 0.0
    for chg in plan.changes:
        unit = _MONTHLY_COST_HEURISTIC_USD.get(chg.resource_type, 10.0)
        if chg.action == "create":
            delta += unit
        elif chg.action == "delete":
            delta -= unit
    return round(delta, 2)


def _compute_blast_score(plan: ParsedPlan) -> int:
    score = 0
    for chg in plan.changes:
        score += _ACTION_WEIGHT.get(chg.action, 0)
    score += len(plan.drifts) * 3
    return score


def build_prometheus_metrics(
    action_counts: dict[str, int],
    drift_count: int,
    violations: list[PolicyViolation],
    blast_score: int,
    cost_delta: float,
) -> str:
    """Format Prometheus text exposition metrics for the evaluated plan."""
    lines = [
        "# HELP drift_gate_resource_changes_total Planned IaC resource changes by action",
        "# TYPE drift_gate_resource_changes_total gauge",
    ]
    for action, count in sorted(action_counts.items()):
        lines.append(f'drift_gate_resource_changes_total{{action="{action}"}} {count}')

    lines.extend(
        [
            "# HELP drift_gate_drift_detected_total Number of resources with out-of-band drift",
            "# TYPE drift_gate_drift_detected_total gauge",
            f"drift_gate_drift_detected_total {drift_count}",
            "# HELP drift_gate_policy_violations_total Policy violations by severity and rule_id",
            "# TYPE drift_gate_policy_violations_total gauge",
        ]
    )
    grouped: dict[tuple[str, str], int] = {}
    for v in violations:
        key = (v.severity, v.rule_id)
        grouped[key] = grouped.get(key, 0) + 1
    if not grouped:
        lines.append('drift_gate_policy_violations_total{severity="none",rule_id="none"} 0')
    else:
        for (sev, rule_id), cnt in sorted(grouped.items()):
            lines.append(
                f'drift_gate_policy_violations_total{{severity="{sev}",rule_id="{rule_id}"}} {cnt}'
            )

    lines.extend(
        [
            "# HELP drift_gate_blast_radius_score Computed blast-radius risk score",
            "# TYPE drift_gate_blast_radius_score gauge",
            f"drift_gate_blast_radius_score {blast_score}",
            "# HELP drift_gate_estimated_monthly_cost_delta_usd Estimated monthly USD cost delta",
            "# TYPE drift_gate_estimated_monthly_cost_delta_usd gauge",
            f"drift_gate_estimated_monthly_cost_delta_usd {cost_delta}",
        ]
    )
    return "\n".join(lines) + "\n"


def evaluate_plan(
    plan: ParsedPlan,
    violations: list[PolicyViolation],
    max_destroys: int,
    engines_used: list[str],
) -> EvaluationReport:
    """Combine drift, policy, and blast-radius evaluations with strict exit codes.

    Exit codes:
      0: Clean pass (no policy violations, no blast-radius breach, no drift)
      2: Policy violation or blast-radius destroy gate breach
      3: Out-of-band drift detected (with no policy violations)
    """
    counts = plan.action_counts
    destroys_total = counts.get("delete", 0) + counts.get("replace", 0)
    blast_exceeded = destroys_total > max_destroys

    all_violations = list(violations)
    if blast_exceeded:
        all_violations.append(
            PolicyViolation(
                rule_id="blast_radius_max_destroys",
                severity="critical",
                address="plan",
                resource_type="blast_radius",
                message=(
                    f"Plan destroys/replaces {destroys_total} resources, "
                    f"exceeding max_destroys={max_destroys}."
                ),
                remediation="Split destructive changes or increase --max-destroys after review.",
                engine="blast-radius",
            )
        )

    drift_count = len(plan.drifts)
    if all_violations:
        exit_code = 2
        status = "POLICY_VIOLATION"
    elif drift_count > 0:
        exit_code = 3
        status = "DRIFT_DETECTED"
    else:
        exit_code = 0
        status = "PASS"

    blast_score = _compute_blast_score(plan)
    cost_delta = _estimate_cost_delta(plan)
    prom = build_prometheus_metrics(counts, drift_count, all_violations, blast_score, cost_delta)

    return EvaluationReport(
        exit_code=exit_code,
        status=status,
        engines_used=engines_used,
        action_counts=counts,
        destroys_total=destroys_total,
        max_destroys_allowed=max_destroys,
        blast_radius_exceeded=blast_exceeded,
        blast_radius_score=blast_score,
        estimated_monthly_cost_delta_usd=cost_delta,
        drift_count=drift_count,
        drifts=[d.model_dump() for d in plan.drifts],
        violation_count=len(all_violations),
        violations=all_violations,
        prometheus_metrics=prom,
    )


def render_markdown(report: EvaluationReport) -> str:
    """Render a clean PR-ready Markdown summary for GitHub Actions."""
    c = report.action_counts
    lines: list[str] = [
        f"## Drift Gate Report: **{report.status}** (exit `{report.exit_code}`)",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Create / Update / Replace / Delete | "
        f"+{c['create']} / ~{c['update']} / ±{c['replace']} / -{c['delete']} |",
        f"| Out-of-Band Drift Detected | {report.drift_count} |",
        f"| Policy Violations | {report.violation_count} |",
        f"| Blast-Radius Score | {report.blast_radius_score} |",
        f"| Est. Monthly Cost Delta | ${report.estimated_monthly_cost_delta_usd:+.2f}/mo |",
        "",
    ]

    if report.violations:
        lines.extend(
            [
                "### Policy Violations",
                "| Severity | Rule | Resource | Message |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for v in report.violations:
            lines.append(
                f"| **{v.severity.upper()}** | `{v.rule_id}` | `{v.address}` | {v.message} |"
            )
        lines.append("")

    if report.drifts:
        lines.extend(
            [
                "### Out-of-Band Drift",
                "| Resource | Type | Actions | Changed Attributes |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for d in report.drifts:
            attrs = ", ".join(str(a) for a in d.get("changed_attributes", [])) or "none"
            acts = ", ".join(str(a) for a in d.get("actions", []))
            lines.append(f"| `{d['address']}` | `{d['resource_type']}` | `{acts}` | `{attrs}` |")
        lines.append("")

    return "\n".join(lines)
