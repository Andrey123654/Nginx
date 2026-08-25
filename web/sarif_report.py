"""SARIF 2.1.0 export for CI/CD and GitHub code scanning."""

import json
import re


def _level(severity):
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "warning")


def _safe_uri(value):
    value = str(value or "uploaded-nginx.conf").replace("\\", "/").split("/")[-1]
    return re.sub(r"[^A-Za-z0-9._-]", "_", value) or "uploaded-nginx.conf"


def generate_sarif_report(report):
    findings = report.get("findings", [])
    rules = {}
    results = []
    for item in findings:
        rule_id = str(item.get("rule") or "nginx-scope-finding")
        references = item.get("references") or []
        rule = {
            "id": rule_id,
            "name": rule_id.replace("-", "_"),
            "shortDescription": {"text": str(item.get("message") or rule_id)},
            "help": {"text": str(item.get("recommendation") or "Проверьте конфигурацию вручную.")},
            "properties": {"tags": ["security", "nginx", str(item.get("severity") or "warning")]},
        }
        if references:
            rule["helpUri"] = str(references[0].get("url"))
        rules.setdefault(rule_id, rule)

        source = _safe_uri(item.get("source") or item.get("resource"))
        line = item.get("line")
        location = {"physicalLocation": {"artifactLocation": {"uri": source}}}
        if isinstance(line, int) and line > 0:
            location["physicalLocation"]["region"] = {"startLine": line}
        result = {
            "ruleId": rule_id,
            "level": _level(item.get("severity")),
            "message": {"text": str(item.get("message") or rule_id)},
            "locations": [location],
            "properties": {
                "resource": str(item.get("resource") or ""),
                "evidence": str(item.get("evidence") or ""),
                "recommendation": str(item.get("recommendation") or ""),
            },
        }
        results.append(result)

    value = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "NGINX Scope",
                "informationUri": "https://github.com/Andrey123654/Nginx",
                "version": "1.5.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
