"""Entity resolution: attribute each asset to an owning team, then match its software to CVEs.

Ownership is decided by rules applied in order, and every match records which rule fired,
so attribution is explainable and auditable:
  1. exact   - cleaned hostname equals an owner record
  2. fuzzy   - hostname similarity above a threshold (handles 'PAYAPI02' vs 'pay-api-02')
  3. subnet  - IP falls inside a network range owned by a team
  4. none    - left unattributed and flagged by data-quality checks
"""
import ipaddress
from difflib import SequenceMatcher

import pandas as pd

from .versions import in_range


def _best_fuzzy(key: str, candidates: pd.Series) -> tuple[int | None, float]:
    best_idx, best = None, 0.0
    for idx, cand in candidates.items():
        score = SequenceMatcher(None, key, cand).ratio()
        if score > best:
            best_idx, best = idx, score
    return best_idx, best


def attribute_owners(assets: pd.DataFrame, owners: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    threshold = cfg["matching"]["hostname_similarity_threshold"]
    subnets = [(ipaddress.ip_network(r["cidr"]), r["team"]) for r in cfg["subnet_owners"]]
    by_key = owners.set_index("host_key")
    out = []
    for _, a in assets.iterrows():
        rec = {"asset_id": a.asset_id, "team": None, "business_unit": None,
               "criticality_tier": "tier3", "match_rule": "none", "match_score": 0.0}
        if a.host_key in by_key.index:
            o = by_key.loc[a.host_key]
            rec.update(team=o.team, business_unit=o.business_unit, criticality_tier=o.criticality_tier,
                       match_rule="exact", match_score=1.0)
        else:
            idx, score = _best_fuzzy(a.host_key, owners["host_key"])
            if idx is not None and score >= threshold:
                o = owners.loc[idx]
                rec.update(team=o.team, business_unit=o.business_unit, criticality_tier=o.criticality_tier,
                           match_rule="fuzzy", match_score=round(score, 2))
            else:
                ip = ipaddress.ip_address(a.ip)
                for net, team in subnets:
                    if ip in net:
                        rec.update(team=team, match_rule="subnet", match_score=0.5)
                        break
        out.append(rec)
    return assets.merge(pd.DataFrame(out), on="asset_id")


def match_vulnerabilities(software: pd.DataFrame, cves: pd.DataFrame) -> pd.DataFrame:
    joined = software.merge(cves, on="product", how="inner")
    if "max_inclusive" not in joined:
        joined["max_inclusive"] = True
    joined["max_inclusive"] = joined["max_inclusive"].fillna(True).astype(bool)
    mask = joined.apply(lambda r: in_range(r.version, r.min_version, r.max_version, r.max_inclusive), axis=1)
    return joined[mask][["asset_id", "product", "version", "cve_id", "cvss", "summary"]].reset_index(drop=True)
