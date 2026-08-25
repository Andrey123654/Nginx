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
