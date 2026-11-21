"""Parser for OpenTofu and Terraform `show -json <planfile>` outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

ChangeAction = Literal["create", "update", "delete", "replace", "read", "no-op"]


class ResourceChange(BaseModel):
    """Normalized resource change entry from a Terraform/OpenTofu plan."""

    address: str
    resource_type: str
    name: str
    provider_name: str = ""
    action: ChangeAction
    actions_raw: list[str] = Field(default_factory=list)
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    changed_attributes: list[str] = Field(default_factory=list)


class DriftItem(BaseModel):
    """Out-of-band drift record detected in `resource_drift`."""

    address: str
    resource_type: str
    name: str
    actions: list[str] = Field(default_factory=list)
    changed_attributes: list[str] = Field(default_factory=list)
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)


class ParsedPlan(BaseModel):
    """Structured representation of an OpenTofu/Terraform JSON plan."""

    format_version: str = ""
    terraform_version: str = ""
    changes: list[ResourceChange] = Field(default_factory=list)
    drifts: list[DriftItem] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def action_counts(self) -> dict[str, int]:
        counts = {"create": 0, "update": 0, "delete": 0, "replace": 0, "no-op": 0, "read": 0}
        for chg in self.changes:
            counts[chg.action] = counts.get(chg.action, 0) + 1
        return counts


def _classify_actions(actions: list[str]) -> ChangeAction:
    normalized = [str(a).lower() for a in actions]
    if set(normalized) == {"create", "delete"}:
        return "replace"
    if "delete" in normalized:
        return "delete"
    if "create" in normalized:
        return "create"
    if "update" in normalized:
        return "update"
    if "read" in normalized:
        return "read"
    return "no-op"


def _diff_keys(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    keys = sorted(set(before) | set(after))
    return [k for k in keys if before.get(k) != after.get(k)]


def parse_plan_dict(data: dict[str, Any]) -> ParsedPlan:
    """Parse an already-loaded OpenTofu/Terraform plan JSON dictionary."""
    changes: list[ResourceChange] = []
    for item in data.get("resource_changes", []) or []:
        change = item.get("change") or {}
        actions = [str(a) for a in (change.get("actions") or ["no-op"])]
        before = change.get("before") if isinstance(change.get("before"), dict) else {}
        after = change.get("after") if isinstance(change.get("after"), dict) else {}
        action = _classify_actions(actions)
        changes.append(
            ResourceChange(
                address=str(item.get("address") or ""),
                resource_type=str(item.get("type") or ""),
                name=str(item.get("name") or ""),
                provider_name=str(item.get("provider_name") or ""),
                action=action,
                actions_raw=actions,
                before=before,
                after=after,
                changed_attributes=_diff_keys(before, after),
            )
        )

    drifts: list[DriftItem] = []
    for item in data.get("resource_drift", []) or []:
        change = item.get("change") or {}
        actions = [str(a) for a in (change.get("actions") or [])]
        if actions == ["no-op"]:
            continue
        before = change.get("before") if isinstance(change.get("before"), dict) else {}
        after = change.get("after") if isinstance(change.get("after"), dict) else {}
        drifts.append(
            DriftItem(
                address=str(item.get("address") or ""),
                resource_type=str(item.get("type") or ""),
                name=str(item.get("name") or ""),
                actions=actions,
                changed_attributes=_diff_keys(before, after),
                before=before,
                after=after,
            )
        )

    return ParsedPlan(
        format_version=str(data.get("format_version") or ""),
        terraform_version=str(data.get("terraform_version") or ""),
        changes=changes,
        drifts=drifts,
        raw=data,
    )


def parse_plan_file(plan_path: Path | str) -> ParsedPlan:
    """Load and parse a Terraform/OpenTofu plan JSON file from disk."""
    path = Path(plan_path)
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in plan file: {path}")
    return parse_plan_dict(data)
