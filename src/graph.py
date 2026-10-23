"""Relationship model: teams OWN assets, assets RUN software, software is AFFECTED_BY CVEs."""
import networkx as nx
import pandas as pd


def build_graph(attributed: pd.DataFrame, software: pd.DataFrame, findings: pd.DataFrame) -> nx.DiGraph:
    g = nx.DiGraph()
    for _, a in attributed.iterrows():
        g.add_node(a.asset_id, kind="asset", hostname=a.hostname, tier=a.criticality_tier)
        if pd.notna(a.team) and a.team:
            g.add_node(a.team, kind="team")
            g.add_edge(a.team, a.asset_id, rel="OWNS", rule=a.match_rule)
    for _, s in software.iterrows():
        sw = f"{s['product']}@{s['version'] or 'unknown'}"
        g.add_node(sw, kind="software")
        g.add_edge(s.asset_id, sw, rel="RUNS")
    for _, f in findings.iterrows():
        g.add_node(f.cve_id, kind="cve", cvss=f.cvss)
        g.add_edge(f"{f['product']}@{f['version']}", f.cve_id, rel="AFFECTED_BY")
    return g


def team_risk(g: nx.DiGraph, weights: dict) -> pd.DataFrame:
    """Walk team -> asset -> software -> CVE and sum CVSS weighted by the asset's criticality tier."""
    rows = []
    for team in (n for n, d in g.nodes(data=True) if d["kind"] == "team"):
        score, cves, assets = 0.0, set(), set()
        for asset in g.successors(team):
            w = weights.get(g.nodes[asset]["tier"], 1.0)
            for sw in g.successors(asset):
                for cve in g.successors(sw):
                    score += (g.nodes[cve].get("cvss") or 0) * w
                    cves.add(cve)
                    assets.add(asset)
        rows.append({"team": team, "risk_score": round(score, 1), "open_cves": len(cves), "affected_assets": len(assets)})
    return pd.DataFrame(rows).sort_values("risk_score", ascending=False).reset_index(drop=True)
