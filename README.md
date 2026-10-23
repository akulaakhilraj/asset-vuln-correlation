# Asset Ownership & Vulnerability Correlation Pipeline

A Python data pipeline that answers a common security question: **which team owns each vulnerable asset, and which teams carry the most risk?**

It pulls vulnerability data (CVEs) from the NVD API, normalizes a messy asset inventory, attributes each asset to an owning team using rule-based entity resolution, matches installed software against CVE version ranges, and models everything as a graph so risk can be rolled up by team and business criticality.

## Why this problem is hard

Security data comes from many systems that don't share clean keys. The same server can show up as `pay-api-02.prod.corp` in one tool and `PAYAPI02` in another, some assets have no owner record at all, and software versions use formats like `1.0.1f` or `9.3p1` that don't sort correctly as plain strings. Unattributed vulnerabilities don't get fixed, so ownership accuracy directly affects time to remediation.

## How it works

```
NVD API (JSON) ─┐
                ├─> normalize ─> attribute owners ─> match CVEs ─> graph ─> team risk
asset inventory ┘        │            │                                   │
owner records ───────────┘            └── quality checks ─────────────────┘
```

1. **Ingest** – Calls the NVD CVE 2.0 API by keyword and flattens each CVE's vulnerable version ranges. Falls back to bundled sample data when offline.
2. **Normalize** – Deduplicates assets, standardizes product names, and cleans hostnames (lowercase, strip domain and punctuation).
3. **Attribute owners (entity resolution)** – Rules run in order, and every match records which rule fired so results are explainable:
   - `exact`: cleaned hostname matches an owner record
   - `fuzzy`: hostname similarity ≥ 0.85 (catches `idp-auth-02` vs `idp-auth-01.prod.corp`)
   - `subnet`: IP falls in a network range owned by a team (rules in `config/pipeline.yaml`)
   - `none`: left unattributed and flagged
4. **Match vulnerabilities** – Compares installed versions to CVE ranges with a custom version parser that handles letter suffixes and inclusive/exclusive bounds.
5. **Graph model** – Builds a NetworkX graph: `team -OWNS-> asset -RUNS-> software -AFFECTED_BY-> CVE`. Team risk = sum of CVSS scores weighted by each asset's criticality tier.
6. **Data quality** – Checks duplicate IDs, unattributed asset %, missing versions, vulnerabilities on unowned assets, and low-confidence matches. Thresholds are set in YAML.
7. **Optional AI step** – If `ANTHROPIC_API_KEY` is set, Claude suggests owners for unattributed assets. Suggestions go to a review file and are never applied automatically; a person confirms them and adds a rule.

## Run it

```bash
pip install -r requirements.txt
python -m src.pipeline --sample     # fast run with bundled sample CVEs (a few seconds)
python -m src.pipeline              # live run against the NVD API (about 45 seconds)
python -m unittest -v               # run the tests
```

Outputs land in `outputs/`:

| File | What it shows |
|---|---|
| `asset_ownership.csv` | Each asset's team, business unit, tier, and the rule that matched it |
| `vulnerability_findings.csv` | Each CVE found on each asset, sorted by CVSS |
| `team_risk.csv` | Teams ranked by criticality-weighted risk |
| `quality_report.csv` | Data-quality results for the run |

Sample run:

```
Team risk ranking:
             team  risk_score  open_cves  affected_assets
Customer Identity        59.4          2                1
Payments Platform        45.6          2                1
    Data Platform        29.4          1                2
 Digital Channels        15.0          1                1
```

The quality report also flags `A-008`, a legacy server running OpenSSL 1.0.1f (Heartbleed) with no owner, which is exactly the kind of gap this pipeline exists to surface.

## Project layout

```
config/pipeline.yaml   NVD settings, ownership rules, criticality weights, quality thresholds
data/                  sample asset inventory, owner records, offline CVE sample
src/                   ingest, normalize, resolve, graph, quality, llm_assist, pipeline
dags/                  Airflow DAG that runs the pipeline every 6 hours
tests/                 unit tests for version matching, attribution rules and CVE matching
```

## Notes

- The bundled `sample_cves.json` uses real CVE IDs with simplified version ranges so the project runs offline. Live runs use the NVD API.
- The asset inventory and owner records are synthetic.

## Ideas for next steps

- Load the graph into Neo4j and query it with Cypher
- Add CPE-based matching instead of keyword search
- Track attribution coverage and mean time to remediation over time
