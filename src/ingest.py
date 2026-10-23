"""Pull CVE data from the NVD API, falling back to bundled sample data when offline."""
import json
import logging
import time
from pathlib import Path

import requests

log = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]


# Keyword -> product name as it appears in NVD CPE strings, so only matching products are kept.
CPE_PRODUCT = {"apache http server": "http_server"}


def _parse_nvd(payload: dict, product: str) -> list[dict]:
    """Flatten NVD 2.0 JSON into one row per (CVE, affected version range) for the given product."""
    cpe_name = CPE_PRODUCT.get(product, product.replace(" ", "_"))
    rows = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0]["cvssData"]["baseScore"]
                break
        summary = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable"):
                        continue
                    # cpe:2.3:a:<vendor>:<product>:... keep only the product we searched for
                    parts = match.get("criteria", "").split(":")
                    if len(parts) < 5 or parts[4] != cpe_name:
                        continue
                    has_range = any(k in match for k in ("versionStartIncluding", "versionEndIncluding", "versionEndExcluding"))
                    if has_range:
                        min_v = match.get("versionStartIncluding", "0")
                        max_v = match.get("versionEndIncluding") or match.get("versionEndExcluding", "")
                        max_inclusive = "versionEndExcluding" not in match
                    else:
                        # No range: the CPE names one exact version, e.g. ...:openssl:1.0.1:f:... -> 1.0.1f
                        ver = parts[5] if len(parts) > 5 else "*"
                        upd = parts[6] if len(parts) > 6 else "*"
                        if ver in ("*", "-"):
                            continue
                        exact = ver + (upd if upd not in ("*", "-") else "")
                        min_v = max_v = exact
                        max_inclusive = True
                    if not max_v:
                        continue
                    rows.append({
                        "cve_id": cve.get("id"),
                        "product": product,
                        "min_version": min_v,
                        "max_version": max_v,
                        "max_inclusive": max_inclusive,
                        "cvss": cvss,
                        "summary": summary[:200],
                    })
    return rows


def load_sample_cves() -> list[dict]:
    return json.loads((ROOT / "data" / "sample_cves.json").read_text())


def fetch_cves(cfg: dict, use_sample: bool = False) -> list[dict]:
    if use_sample:
        log.info("Using bundled sample CVEs (--sample)")
        return load_sample_cves()
    nvd = cfg["nvd"]
    rows = []
    kws = nvd["keywords"]
    log.info("Fetching CVEs from NVD for %d keywords (about %d seconds, NVD rate limit)...", len(kws), len(kws) * 7)
    try:
        for i, kw in enumerate(kws, 1):
            log.info("  [%d/%d] %s", i, len(kws), kw)
            r = requests.get(nvd["api_url"], params={"keywordSearch": kw, "resultsPerPage": nvd["results_per_keyword"]}, timeout=20)
            r.raise_for_status()
            rows.extend(_parse_nvd(r.json(), kw))
            if i < len(kws):
                time.sleep(6)  # NVD allows ~5 requests per 30s without an API key
        log.info("Fetched %d CVE rows from NVD", len(rows))
        if rows:
            return rows
    except requests.RequestException as e:
        if not nvd.get("use_sample_if_offline"):
            raise
        log.warning("NVD unreachable (%s); using bundled sample CVEs", e.__class__.__name__)
    return load_sample_cves()


def load_assets() -> list[dict]:
    return json.loads((ROOT / "data" / "assets.json").read_text())
