import unittest

import pandas as pd

from src import normalize, resolve
from src.ingest import _parse_nvd
from src.versions import in_range

CFG = {
    "matching": {"hostname_similarity_threshold": 0.85},
    "subnet_owners": [{"cidr": "10.30.0.0/16", "team": "Data Platform"}],
}
OWNERS = normalize.normalize_owners(pd.DataFrame([
    {"hostname": "pay-api-01.prod.corp", "team": "Payments", "business_unit": "Pay", "criticality_tier": "tier1"},
]))


class VersionTests(unittest.TestCase):
    def test_letter_suffixes(self):
        self.assertTrue(in_range("1.0.1f", "1.0.1", "1.0.1f"))
        self.assertFalse(in_range("1.0.1g", "1.0.1", "1.0.1f"))
        self.assertTrue(in_range("1.0.1", "1.0.1", "1.0.1f"))

    def test_openssh_style(self):
        self.assertTrue(in_range("8.9p1", "0", "9.3p1"))
        self.assertFalse(in_range("9.6p1", "0", "9.3p1"))

    def test_exclusive_upper_bound(self):
        self.assertFalse(in_range("2.17.0", "2.0", "2.17.0", max_inclusive=False))
        self.assertTrue(in_range("2.16.0", "2.0", "2.17.0", max_inclusive=False))

    def test_unknown_version_never_matches(self):
        self.assertFalse(in_range("", "0", "99"))


class AttributionTests(unittest.TestCase):
    def _attribute(self, hostname, ip):
        assets = pd.DataFrame([{"asset_id": "X", "hostname": hostname, "ip": ip}])
        assets["host_key"] = assets.hostname.map(normalize.clean_hostname)
        return resolve.attribute_owners(assets, OWNERS, CFG).iloc[0]

    def test_exact_match_ignores_case_and_domain(self):
        self.assertEqual(self._attribute("PAY-API-01", "1.1.1.1").match_rule, "exact")

    def test_fuzzy_match(self):
        r = self._attribute("payapi01-dr", "1.1.1.1")
        self.assertEqual((r.match_rule, r.team), ("fuzzy", "Payments"))

    def test_subnet_fallback(self):
        r = self._attribute("random-box", "10.30.5.5")
        self.assertEqual((r.match_rule, r.team), ("subnet", "Data Platform"))

    def test_unattributed(self):
        self.assertEqual(self._attribute("random-box", "192.168.1.1").match_rule, "none")


class VulnMatchTests(unittest.TestCase):
    def test_matches_only_vulnerable_versions(self):
        sw = pd.DataFrame([{"asset_id": "A", "product": "log4j", "version": "2.14.1"},
                           {"asset_id": "B", "product": "log4j", "version": "2.17.1"}])
        cves = pd.DataFrame([{"cve_id": "CVE-2021-44228", "product": "log4j", "min_version": "2.0",
                              "max_version": "2.14.1", "cvss": 10.0, "summary": ""}])
        out = resolve.match_vulnerabilities(sw, cves)
        self.assertEqual(list(out.asset_id), ["A"])


class NvdParseTests(unittest.TestCase):
    def _payload(self, match):
        return {"vulnerabilities": [{"cve": {"id": "CVE-T", "metrics": {}, "descriptions": [],
                                             "configurations": [{"nodes": [{"cpeMatch": [match]}]}]}}]}

    def test_exact_version_cpe(self):
        rows = _parse_nvd(self._payload({"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:1.0.1:f:*:*:*:*:*:*"}), "openssl")
        self.assertEqual((rows[0]["min_version"], rows[0]["max_version"]), ("1.0.1f", "1.0.1f"))

    def test_other_products_are_skipped(self):
        rows = _parse_nvd(self._payload({"vulnerable": True, "criteria": "cpe:2.3:a:vendor:other:1.0:*:*:*:*:*:*:*"}), "openssl")
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
