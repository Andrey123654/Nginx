import datetime as dt
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

import audit


class AuditTests(unittest.TestCase):
    def inventory(self):
        return {"schema_version": 1, "max_sensor_age_hours": 12, "targets": [{
            "id": "admin", "name": "Admin", "owner": "sec@example.invalid", "criticality": "critical",
            "urls": ["https://admin.example.invalid/"], "expected_visibility": ["internal"],
            "expected_cidrs": {"internal": ["10.0.0.0/8"]},
        }]}

    def sensor(self, zone, reachable, address):
        return {"kind": "sensor", "zone": zone, "collected_at": audit.now_utc(), "findings": [], "targets": [{
            "id": "admin", "probes": [{"reachable": reachable, "addresses": [address]}]
        }]}

    def test_unexpected_external_exposure_is_critical(self):
        report = audit.aggregate_data(self.inventory(), [
            self.sensor("internal", True, "10.1.2.3"), self.sensor("external", True, "198.51.100.4")
        ], [])
        self.assertEqual(report["resources"][0]["status"], "unexpected_exposure")
        finding = next(x for x in report["findings"] if x["rule"] == "unexpected-exposure")
        self.assertEqual(finding["severity"], "critical")

    def test_missing_sensor_makes_status_unknown(self):
        report = audit.aggregate_data(self.inventory(), [self.sensor("internal", True, "10.1.2.3")], [])
        self.assertEqual(report["resources"][0]["status"], "unknown")

    def test_nginx_config_rules(self):
        config = "events {} http { server { listen 443 ssl; ssl_protocols TLSv1 TLSv1.2; autoindex on; } }"
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "out.json")
            args = mock.Mock(source="proxy-1", output=output)
            with mock.patch("sys.stdin", io.StringIO(config)):
                audit.nginx_config(args)
            rules = {x["rule"] for x in audit.read_json(output)["findings"]}
        self.assertIn("nginx-old-tls", rules)
        self.assertIn("nginx-autoindex", rules)
        self.assertIn("nginx-server-tokens", rules)

    def test_credentials_in_url_are_rejected(self):
        value = self.inventory()
        value["targets"][0]["urls"] = ["https://user:secret@example.invalid/"]
        with self.assertRaises(ValueError):
            audit.validate_inventory(value)

    def test_corrected_config_applies_safe_hardening(self):
        config = "events {} http { server { listen 443 ssl; ssl_protocols TLSv1 TLSv1.2; autoindex on; } }"
        fixed, applied, manual = audit.build_corrected_nginx_config(config)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", fixed)
        self.assertIn("autoindex off;", fixed)
        self.assertIn("Strict-Transport-Security", fixed)
        self.assertIn("listen 80 default_server;", fixed)
        self.assertTrue(applied)
        self.assertTrue(any("Content-Security-Policy" in item for item in manual))

    def test_publications_have_separate_visibility_and_analytics(self):
        config = """events {} http {
          server { listen 0.0.0.0:80; server_name public.example; location /admin { proxy_pass http://app; } }
          server { listen 10.2.3.4:8080; server_name internal.example; access_log off; }
        }"""
        publications = audit.extract_publications(config)
        self.assertEqual(len(publications), 2)
        self.assertEqual(publications[0]["declared_visibility"], ["external", "internal"])
        self.assertEqual(publications[1]["declared_visibility"], ["internal"])
        rules = {item["rule"] for item in publications[0]["findings"]}
        self.assertIn("publication-cleartext", rules)
        self.assertIn("publication-sensitive-endpoint-open", rules)
        summary = publications[0]["summary"]
        self.assertIn("public.example", summary["text"])
        self.assertIn("наружу", summary["exposure"])
        self.assertIn("Оценка", summary["security"])
        location_help = publications[0]["locations"][0]["explanation"]
        self.assertEqual(location_help["match_type"], "Префиксный маршрут")
        self.assertTrue(any(item["name"] == "proxy_pass" for item in location_help["directives"]))

    def test_publication_baseline_omits_raw_config(self):
        publications = audit.extract_publications("events {} http { server { listen 80; server_name app.example; } }")
        baseline = audit.build_publication_baseline(publications, "nginx.conf")
        self.assertNotIn("config_excerpt", json.dumps(baseline))
        self.assertEqual(audit.compare_publication_baseline(publications, baseline)["status"], "unchanged")

    def test_corrected_config_does_not_flag_protective_default_as_vulnerable(self):
        config = "events {} http { server { listen 443 ssl; server_name app.example; } }"
        corrected, _, _ = audit.build_corrected_nginx_config(config)
        publications = audit.extract_publications(corrected)
        catch_all = next(item for item in publications if item["publication_type"] == "protective_default")
        self.assertEqual(catch_all["findings"], [])
        self.assertEqual(catch_all["score"], 100)
        before = audit.analyze_nginx_text(config) + [finding for item in audit.extract_publications(config) for finding in item["findings"]]
        after = audit.analyze_nginx_text(corrected) + [finding for item in publications for finding in item["findings"]]
        self.assertLessEqual(len(after), len(before))
        tls_block = next(item["config_excerpt"] for item in publications if item["tls"])
        self.assertIn("X-Content-Type-Options", tls_block)

    def test_testssl_findings_are_normalized(self):
        sensor = self.sensor("internal", True, "10.1.2.3")
        sensor["targets"][0]["probes"][0]["url"] = "https://admin.example.invalid/"
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "testssl-" + audit.safe_filename("https://admin.example.invalid/") + ".json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump([{"id": "TLS1", "severity": "HIGH", "finding": "TLS 1.0 enabled"}], fh)
            findings, count = audit.read_testssl_findings(directory, sensor)
        self.assertEqual(count, 1)
        self.assertEqual(findings[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
