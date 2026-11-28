"""SKU-aware cloud pricing resolver backed by Focus Ledger /v1/pricing/sku."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from drift_gate.parser import ResourceChange

BUILTIN_SKU_PRICING: dict[str, dict[str, float]] = {
    "aws_db_instance": {
        "default": 145.0,
        "db.t3.micro": 14.5,
        "db.t3.medium": 58.0,
        "db.r6g.large": 189.0,
        "db.r6g.xlarge": 378.0,
        "db.r6g.4xlarge": 1512.0,
    },
    "aws_rds_cluster": {
        "default": 290.0,
        "db.r6g.large": 210.0,
        "db.r6g.4xlarge": 1680.0,
    },
    "aws_instance": {
        "default": 68.0,
        "t3.micro": 7.6,
        "m6i.large": 70.08,
        "m6i.xlarge": 140.16,
        "m6i.2xlarge": 280.32,
        "c6i.xlarge": 124.10,
        "c6i.2xlarge": 248.20,
    },
    "aws_eks_cluster": {"default": 73.0},
    "aws_nat_gateway": {"default": 33.0},
    "aws_lb": {"default": 22.0},
    "aws_s3_bucket": {"default": 5.0},
    "google_sql_database_instance": {
        "default": 140.0,
        "db-custom-2-8192": 112.0,
        "db-custom-8-32768": 448.0,
    },
    "azurerm_mssql_server": {"default": 150.0},
}


def extract_instance_sku(chg: ResourceChange) -> str | None:
    """Extract cloud SKU / instance size from Terraform/OpenTofu resource attributes."""
    attrs = chg.after if chg.action != "delete" else chg.before
    for key in ("instance_class", "instance_type", "machine_type", "vm_size", "tier"):
        val = attrs.get(key)
        if val:
            return str(val)
    settings = attrs.get("settings")
    if isinstance(settings, list) and settings and isinstance(settings[0], dict):
        if settings[0].get("tier"):
            return str(settings[0]["tier"])
    return None


class SKUPricingResolver:
    """Resolves monthly USD resource costs via Focus Ledger API with local fallback."""

    def __init__(self, focus_ledger_url: str | None = None) -> None:
        self.focus_ledger_url = focus_ledger_url.rstrip("/") if focus_ledger_url else None
        self._cache: dict[tuple[str, str], float] = {}

    def monthly_cost(self, resource_type: str, instance_sku: str | None = None) -> float:
        rtype = resource_type.strip().lower()
        sku = instance_sku.strip().lower() if instance_sku else "default"
        cache_key = (rtype, sku)
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self.focus_ledger_url:
            query = urllib.parse.urlencode({"resource_type": rtype, "instance_type": sku})
            url = f"{self.focus_ledger_url}/v1/pricing/sku?{query}"
            try:
                req = urllib.request.Request(url, headers={"Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=2.5) as resp:  # noqa: S310
                    payload: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
                    if "monthly_usd" in payload:
                        val = float(payload["monthly_usd"])
                        self._cache[cache_key] = val
                        return val
            except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError):
                pass

        table = BUILTIN_SKU_PRICING.get(rtype, {})
        val = float(table.get(sku, table.get("default", 10.0)))
        self._cache[cache_key] = val
        return val
