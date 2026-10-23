"""Run the full pipeline: ingest -> normalize -> attribute owners -> match CVEs -> graph -> quality -> reports."""
import argparse
import logging
from pathlib import Path

import pandas as pd
import yaml

from . import graph, ingest, llm_assist, normalize, quality, resolve

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs"


def run(use_sample: bool = False) -> dict:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = yaml.safe_load((ROOT / "config" / "pipeline.yaml").read_text())

    raw_assets = ingest.load_assets()
    assets, software = normalize.normalize_assets(raw_assets)
    owners = normalize.normalize_owners(pd.read_csv(ROOT / "data" / "owners.csv"))
    cves = normalize.normalize_cves(ingest.fetch_cves(cfg, use_sample))

    attributed = resolve.attribute_owners(assets, owners, cfg)
    findings = resolve.match_vulnerabilities(software, cves)
    g = graph.build_graph(attributed, software, findings)
    risk = graph.team_risk(g, cfg["criticality_weights"])
    checks = quality.run_checks(raw_assets, attributed, software, findings, cfg)

    OUT.mkdir(exist_ok=True)
    attributed.drop(columns="host_key").to_csv(OUT / "asset_ownership.csv", index=False)
    findings.merge(attributed[["asset_id", "hostname", "team", "criticality_tier"]], on="asset_id") \
        .sort_values("cvss", ascending=False).to_csv(OUT / "vulnerability_findings.csv", index=False)
    risk.to_csv(OUT / "team_risk.csv", index=False)
    checks.to_csv(OUT / "quality_report.csv", index=False)

    suggestions = llm_assist.suggest_owners(attributed, owners)
    if suggestions is not None:
        logging.info("Wrote %d LLM owner suggestions for human review", len(suggestions))

    logging.info("Assets: %d | Findings: %d | Graph: %d nodes, %d edges",
                 len(attributed), len(findings), g.number_of_nodes(), g.number_of_edges())
    if (checks.status == "FAIL").any():
        logging.warning("Quality checks failed:\n%s", checks[checks.status == "FAIL"].to_string(index=False))
    return {"attributed": attributed, "findings": findings, "risk": risk, "checks": checks, "graph": g}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Asset ownership and vulnerability correlation pipeline")
    parser.add_argument("--sample", action="store_true", help="use bundled sample CVEs instead of calling the NVD API")
    r = run(use_sample=parser.parse_args().sample)
    print("\nTeam risk ranking:\n", r["risk"].to_string(index=False))
    print("\nQuality report:\n", r["checks"].to_string(index=False))
