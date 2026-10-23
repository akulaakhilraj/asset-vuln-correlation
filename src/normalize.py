"""Normalize raw asset and CVE records into clean, flat tables."""
import re

import pandas as pd


def clean_hostname(h: str) -> str:
    """Lowercase and strip domain suffixes and punctuation so 'PAYAPI02' and 'pay-api-02.prod.corp' compare well."""
    h = (h or "").strip().lower()
    h = h.split(".")[0]
    return re.sub(r"[^a-z0-9]", "", h)


def normalize_assets(raw: list[dict]) -> tuple[pd.DataFrame, pd.DataFrame]:
    assets = pd.DataFrame([{k: a[k] for k in ("asset_id", "hostname", "ip")} for a in raw])
    assets = assets.drop_duplicates("asset_id").reset_index(drop=True)
    assets["host_key"] = assets["hostname"].map(clean_hostname)

    sw = pd.DataFrame([
        {"asset_id": a["asset_id"], "product": s["product"].strip().lower(), "version": (s.get("version") or "").strip()}
        for a in raw for s in a.get("software", [])
    ]).drop_duplicates()
    return assets, sw


def normalize_owners(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["host_key"] = df["hostname"].map(clean_hostname)
    return df


def normalize_cves(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    df["product"] = df["product"].str.lower().str.strip()
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce")
    return df.drop_duplicates(["cve_id", "product", "min_version", "max_version"])
