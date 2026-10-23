"""Data-quality checks that run before results are published."""
import pandas as pd


class QualityError(Exception):
    pass


def run_checks(assets_raw: list[dict], attributed: pd.DataFrame, software: pd.DataFrame, findings: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    q = cfg["quality"]
    n = len(attributed)
    unattributed = attributed[attributed.match_rule == "none"]
    missing_ver = software[software.version == ""]
    dup_ids = len(assets_raw) - len({a["asset_id"] for a in assets_raw})

    results = pd.DataFrame([
        {"check": "duplicate_asset_ids_removed", "value": dup_ids, "status": "WARN" if dup_ids else "PASS"},
        {"check": "unattributed_assets_pct", "value": round(100 * len(unattributed) / n, 1),
         "status": "FAIL" if 100 * len(unattributed) / n > q["max_unattributed_pct"] else "PASS",
         "detail": ", ".join(unattributed.asset_id)},
        {"check": "missing_software_version_pct", "value": round(100 * len(missing_ver) / max(len(software), 1), 1),
         "status": "FAIL" if 100 * len(missing_ver) / max(len(software), 1) > q["max_missing_version_pct"] else "PASS",
         "detail": ", ".join(missing_ver.asset_id)},
        {"check": "findings_on_unowned_assets", "value": int(findings.asset_id.isin(unattributed.asset_id).sum()),
         "status": "WARN" if findings.asset_id.isin(unattributed.asset_id).any() else "PASS",
         "detail": "vulnerabilities with no owner to remediate them"},
        {"check": "fuzzy_or_subnet_matches", "value": int((attributed.match_rule.isin(["fuzzy", "subnet"])).sum()),
         "status": "INFO", "detail": "review lower-confidence ownership matches"},
    ])
    return results
