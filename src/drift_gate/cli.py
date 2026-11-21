"""Typer CLI entrypoint for Drift Gate."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from drift_gate.blast_radius import EvaluationReport, evaluate_plan, render_markdown
from drift_gate.parser import parse_plan_file
from drift_gate.policy import evaluate_policies

app = typer.Typer(
    name="drift-gate",
    help="Open-source IaC drift detection, policy enforcement, and blast-radius gate.",
    no_args_is_help=True,
)
console = Console()


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    markdown = "markdown"


def _render_terminal(report: EvaluationReport) -> None:
    color = {"PASS": "green", "DRIFT_DETECTED": "yellow", "POLICY_VIOLATION": "red"}.get(
        report.status, "white"
    )
    c = report.action_counts
    console.print(
        f"\nDrift Gate: [{color} bold]{report.status}[/{color} bold] "
        f"(exit={report.exit_code}, +create={c['create']}, ~update={c['update']}, "
        f"replace={c['replace']}, -delete={c['delete']}, drift={report.drift_count}, "
        f"blast_score={report.blast_radius_score}, "
        f"est_delta=${report.estimated_monthly_cost_delta_usd:+.2f}/mo)"
    )
    if report.violations:
        tbl = Table(title="Policy Violations", header_style="bold red")
        tbl.add_column("Severity")
        tbl.add_column("Rule")
        tbl.add_column("Resource")
        tbl.add_column("Message")
        for v in report.violations:
            tbl.add_row(v.severity.upper(), v.rule_id, v.address, v.message)
        console.print(tbl)

    if report.drifts:
        tbl = Table(title="Out-of-Band Drift", header_style="bold yellow")
        tbl.add_column("Resource")
        tbl.add_column("Type")
        tbl.add_column("Changed Attributes")
        for d in report.drifts:
            tbl.add_row(
                str(d["address"]),
                str(d["resource_type"]),
                ", ".join(str(a) for a in d.get("changed_attributes", [])),
            )
        console.print(tbl)


@app.callback()
def main() -> None:
    """Evaluate OpenTofu and Terraform JSON plans for drift and policy compliance."""


@app.command()
def version() -> None:
    """Print the installed Drift Gate version."""
    from drift_gate import __version__

    typer.echo(f"drift-gate {__version__}")


@app.command()
def evaluate(
    plan: Path = typer.Option(
        ...,
        "--plan",
        "-p",
        exists=True,
        readable=True,
        help="Path to `tofu show -json` / `terraform show -json` plan file.",
    ),
    policies: Optional[Path] = typer.Option(
        Path("policies"),
        "--policies",
        help="Path to policies directory or YAML rules file.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.terminal,
        "--format",
        "-f",
        help="Output format: terminal, json, or markdown.",
    ),
    max_destroys: Optional[int] = typer.Option(
        None,
        "--max-destroys",
        help="Override maximum allowed destroy/replace operations before gating.",
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        "-o",
        help="Optional path to write formatted report.",
    ),
    metrics_out: Optional[Path] = typer.Option(
        None,
        "--metrics-out",
        help="Optional path to write Prometheus metrics payload (.prom).",
    ),
) -> None:
    """Evaluate a Terraform/OpenTofu JSON plan for drift, policy breaches, and blast radius."""
    parsed = parse_plan_file(plan)
    effective_policies = policies if (policies is not None and policies.exists()) else None
    violations, cfg, engines = evaluate_policies(parsed, effective_policies)
    limit = max_destroys if max_destroys is not None else cfg.max_destroys
    report = evaluate_plan(parsed, violations, max_destroys=limit, engines_used=engines)

    if metrics_out is not None:
        metrics_out.parent.mkdir(parents=True, exist_ok=True)
        metrics_out.write_text(report.prometheus_metrics, encoding="utf-8")

    if output_format == OutputFormat.json:
        rendered = report.model_dump_json(indent=2)
        typer.echo(rendered)
    elif output_format == OutputFormat.markdown:
        rendered = render_markdown(report)
        typer.echo(rendered)
    else:
        _render_terminal(report)
        rendered = render_markdown(report)

    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")

    if report.exit_code != 0:
        raise typer.Exit(code=report.exit_code)


if __name__ == "__main__":
    app()
