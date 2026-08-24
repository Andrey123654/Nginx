#!/usr/bin/env python3
"""Nginx publication visibility and safe misconfiguration audit."""

import argparse
import csv
import datetime as dt
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

SCHEMA_VERSION = 1
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SECURITY_HEADERS = {
    "strict-transport-security": "medium",
    "x-content-type-options": "low",
    "content-security-policy": "medium",
    "referrer-policy": "low",
    "permissions-policy": "low",
}


class SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not let an allowlisted URL redirect the scanner to a third party."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old_host = urllib.parse.urlsplit(req.full_url).hostname
        new_host = urllib.parse.urlsplit(newurl).hostname
        if not new_host or old_host != new_host:
            raise urllib.error.URLError("cross-host redirect blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def now_utc():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def atomic_json(path, value):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".audit-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(value, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def validate_inventory(data):
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported inventory schema_version")
    seen = set()
    for target in data.get("targets", []):
        missing = {"id", "name", "owner", "urls", "expected_visibility"} - set(target)
        if missing:
            raise ValueError("target is missing fields: " + ", ".join(sorted(missing)))
        if target["id"] in seen:
            raise ValueError("duplicate target id: " + target["id"])
        seen.add(target["id"])
        if not target["urls"]:
            raise ValueError("target has no URLs: " + target["id"])
        if not set(target["expected_visibility"]) <= {"external", "internal"}:
            raise ValueError("invalid visibility for: " + target["id"])
        for url in target["urls"]:
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError("only absolute http(s) URLs are allowed: " + url)
            if parsed.username or parsed.password:
                raise ValueError("credentials in URLs are forbidden: " + target["id"])
    return data


def resolve(host):
    try:
        values = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return sorted({item[4][0] for item in values}), None
    except OSError as exc:
        return [], str(exc)


def tls_details(host, port, timeout):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert()
                return {
                    "version": conn.version(),
                    "cipher": conn.cipher()[0] if conn.cipher() else None,
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:20],
                }, None
    except (OSError, ssl.SSLError) as exc:
        return None, str(exc)


def probe_url(url, timeout):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses, dns_error = resolve(host)
    result = {
        "url": url,
        "host": host,
        "port": port,
        "addresses": addresses,
        "dns_error": dns_error,
        "reachable": False,
        "status": None,
        "final_url": None,
        "headers": {},
        "tls": None,
        "errors": [],
    }
    if not addresses:
        return result
    try:
        request = urllib.request.Request(url, headers={
            "User-Agent": "nginx-publication-audit/1", "Range": "bytes=0-0"
        }, method="GET")
        opener = urllib.request.build_opener(SameHostRedirectHandler())
        with opener.open(request, timeout=timeout) as response:
            result["reachable"] = True
            result["status"] = response.status
            result["final_url"] = response.geturl()
            result["headers"] = {k.lower(): v[:1000] for k, v in response.headers.items()}
            response.read(1)
    except urllib.error.HTTPError as exc:
        result["reachable"] = True
        result["status"] = exc.code
        result["final_url"] = exc.geturl()
        result["headers"] = {k.lower(): v[:1000] for k, v in exc.headers.items()}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        result["errors"].append(str(exc))
    if parsed.scheme == "https":
        result["tls"], tls_error = tls_details(host, port, timeout)
        if tls_error:
            result["errors"].append("TLS: " + tls_error)
    return result


def header_findings(target_id, probe):
    findings = []
    if not probe["reachable"]:
        return findings
    headers = probe.get("headers", {})
    if "server" in headers and re.search(r"nginx/\d", headers["server"], re.I):
        findings.append(finding("medium", "nginx-version-disclosure", target_id,
                                "HTTP Server раскрывает версию Nginx", probe["url"]))
    if probe["url"].startswith("https://"):
        for name, severity in SECURITY_HEADERS.items():
            if name not in headers:
                findings.append(finding(severity, "missing-header-" + name, target_id,
                                        "Отсутствует защитный заголовок " + name, probe["url"]))
    if headers.get("access-control-allow-origin") == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
        findings.append(finding("high", "unsafe-cors", target_id,
                                "CORS одновременно разрешает произвольный origin и credentials", probe["url"]))
    return findings


def finding(severity, rule, resource, message, evidence=None):
    value = {"severity": severity, "rule": rule, "resource": resource, "message": message}
    if evidence:
        value["evidence"] = evidence
    return value


def collect(args):
    inventory = validate_inventory(read_json(args.inventory))
    targets = []
    findings = []
    for target in inventory["targets"]:
        probes = [probe_url(url, args.timeout) for url in target["urls"]]
        for probe in probes:
            findings.extend(header_findings(target["id"], probe))
        targets.append({"id": target["id"], "probes": probes})
    output = {
        "schema_version": SCHEMA_VERSION,
        "kind": "sensor",
        "zone": args.zone,
        "collected_at": now_utc(),
        "targets": targets,
        "findings": findings,
        "tools": {"builtin": "1"},
    }
    atomic_json(args.output, output)


def emit_targets(args):
    inventory = validate_inventory(read_json(args.inventory))
    urls = sorted({url for target in inventory["targets"] for url in target["urls"]})
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        for url in urls:
            fh.write(url + "\n")


def parse_jsonl(path):
    values = []
    if not os.path.exists(path):
        return values
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return values


def safe_filename(url):
    return re.sub(r"[^A-Za-z0-9._-]", "_", url)


def normalize_tool_severity(value):
    text = str(value or "info").lower().split()[0]
    aliases = {"warn": "low", "warning": "low", "error": "medium", "fatal": "critical"}
    text = aliases.get(text, text)
    return text if text in SEVERITY_ORDER else "info"


def read_testssl_findings(directory, sensor):
    findings = []
    count = 0
    for target in sensor["targets"]:
        for probe in target["probes"]:
            path = os.path.join(directory, "testssl-" + safe_filename(probe["url"]) + ".json")
            if not os.path.exists(path):
                continue
            try:
                payload = read_json(path)
            except (OSError, json.JSONDecodeError):
                continue
            rows = payload if isinstance(payload, list) else payload.get("scanResult", payload.get("results", []))
            if isinstance(rows, dict):
                rows = [rows]
            for row in rows if isinstance(rows, list) else []:
                if not isinstance(row, dict):
                    continue
                severity = normalize_tool_severity(row.get("severity"))
                if severity == "info" or str(row.get("severity", "")).upper() in {"OK", "INFO"}:
                    continue
                rule = str(row.get("id") or row.get("test") or "tls-check")[:100]
                message = str(row.get("finding") or row.get("message") or rule)[:500]
                findings.append(finding(severity, "testssl:" + rule, target["id"], message, probe["url"]))
                count += 1
    return findings, count


def read_zap_findings(directory, sensor):
    findings = []
    count = 0
    risk_map = {"0": "info", "1": "low", "2": "medium", "3": "high"}
    for target in sensor["targets"]:
        for probe in target["probes"]:
            path = os.path.join(directory, "zap", safe_filename(probe["url"]) + ".json")
            if not os.path.exists(path):
                continue
            try:
                payload = read_json(path)
            except (OSError, json.JSONDecodeError):
                continue
            for site in payload.get("site", []):
                for alert in site.get("alerts", []):
                    severity = risk_map.get(str(alert.get("riskcode")), "info")
                    rule = str(alert.get("pluginid") or "passive-alert")[:100]
                    message = str(alert.get("name") or alert.get("alert") or "ZAP passive alert")[:500]
                    findings.append(finding(severity, "zap:" + rule, target["id"], message, probe["url"]))
                    count += 1
    return findings, count


def enrich(args):
    sensor = read_json(args.sensor)
    directory = args.directory
    httpx = parse_jsonl(os.path.join(directory, "httpx.jsonl"))
    nuclei = parse_jsonl(os.path.join(directory, "nuclei.jsonl"))
    sensor["tools"]["httpx"] = "available" if httpx else "not-run-or-empty"
    sensor["tools"]["nuclei"] = "available" if nuclei else "not-run-or-empty"
    by_url = {}
    for target in sensor["targets"]:
        for probe in target["probes"]:
            by_url[probe["url"].rstrip("/")] = target["id"]
    for row in nuclei:
        matched = (row.get("matched-at") or row.get("host") or "").rstrip("/")
        resource = by_url.get(matched, "unmapped")
        info = row.get("info", {})
        severity = str(info.get("severity", "info")).lower()
        if severity not in SEVERITY_ORDER:
            severity = "info"
        sensor["findings"].append(finding(
            severity, "nuclei:" + str(row.get("template-id", "unknown")), resource,
            str(info.get("name", "Nuclei finding")), matched or None))
    tls_findings, tls_count = read_testssl_findings(directory, sensor)
    zap_findings, zap_count = read_zap_findings(directory, sensor)
    sensor["findings"].extend(tls_findings)
    sensor["findings"].extend(zap_findings)
    sensor["tools"]["testssl"] = "available" if tls_count else "not-run-or-no-findings"
    sensor["tools"]["zap"] = "available" if zap_count else "not-run-or-no-findings"
    sensor["tool_summary"] = {"httpx_records": len(httpx), "nuclei_findings": len(nuclei),
                              "testssl_findings": tls_count, "zap_findings": zap_count}
    atomic_json(args.sensor, sensor)


def strip_comments(line):
    quoted = False
    escaped = False
    result = []
    for char in line:
        if char == '"' and not escaped:
            quoted = not quoted
        if char == "#" and not quoted:
            break
        result.append(char)
        escaped = char == "\\" and not escaped
        if char != "\\":
            escaped = False
    return "".join(result)


def analyze_nginx_text(content, source="uploaded-nginx-config"):
    """Analyze Nginx text without retaining or returning the raw configuration."""
    clean = "\n".join(strip_comments(line) for line in content.splitlines())
    findings = []

    def add(severity, rule, message, evidence=None):
        findings.append(finding(severity, rule, source, message, evidence))

    if not re.search(r"\bserver_tokens\s+off\s*;", clean):
        add("medium", "nginx-server-tokens", "Не найдено глобальное/явное server_tokens off")
    for match in re.finditer(r"\bssl_protocols\s+([^;]+);", clean):
        protocols = match.group(1).split()
        old = sorted(set(protocols) & {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})
        if old:
            add("high", "nginx-old-tls", "Разрешены устаревшие TLS-протоколы", " ".join(old))
    if not re.search(r"\bssl_protocols\s+[^;]*TLSv1\.2", clean):
        add("medium", "nginx-tls-policy-missing", "Не найдена явная политика TLS с TLSv1.2+")
    for match in re.finditer(r"\bautoindex\s+on\s*;", clean):
        add("high", "nginx-autoindex", "Включён листинг каталогов", "autoindex on")
    if re.search(r"\bstub_status\s*;", clean) and not re.search(r"\ballow\s+(?:127\.0\.0\.1|::1|unix:)", clean):
        add("high", "nginx-open-status", "stub_status может быть доступен без локального allowlist")
    if re.search(r"\badd_header\s+Strict-Transport-Security\b", clean, re.I) is None:
        add("medium", "nginx-hsts", "Не найден заголовок Strict-Transport-Security")
    for header, severity in SECURITY_HEADERS.items():
        if header == "strict-transport-security":
            continue
        if re.search(r"\badd_header\s+" + re.escape(header) + r"\b", clean, re.I) is None:
            add(severity, "nginx-header-" + header, "Не найден add_header " + header)
    if re.search(r"location\s+[^\{]*\.\.?.*\{[^}]*\balias\s+", clean, re.S):
        add("high", "nginx-alias-traversal", "Проверьте сочетание location и alias на path traversal")
    if not re.search(r"\blisten\s+[^;]*\bdefault_server\b", clean):
        add("low", "nginx-no-default-server", "Не найден явный default_server/catch-all")
    findings.sort(key=lambda x: (-SEVERITY_ORDER.get(x["severity"], 0), x["rule"]))
    return findings


def nginx_config(args):
    content = sys.stdin.read()
    findings = analyze_nginx_text(content, args.source)
    output = {"schema_version": SCHEMA_VERSION, "kind": "nginx-config", "source": args.source,
              "collected_at": now_utc(), "findings": findings}
    atomic_json(args.output, output)


def in_expected_cidrs(addresses, cidrs):
    if not cidrs:
        return True
    networks = [ipaddress.ip_network(cidr, strict=False) for cidr in cidrs]
    return all(any(ipaddress.ip_address(address) in network for network in networks) for address in addresses)


def parse_time(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def aggregate_data(inventory, sensors, nginx_reports):
    by_zone = {item["zone"]: item for item in sensors if item.get("kind") == "sensor"}
    max_age = dt.timedelta(hours=inventory.get("max_sensor_age_hours", 12))
    current = dt.datetime.now(dt.timezone.utc)
    resources = []
    findings = []
    for sensor in sensors:
        findings.extend(sensor.get("findings", []))
    for report in nginx_reports:
        findings.extend(report.get("findings", []))
    for target in inventory["targets"]:
        actual = []
        addresses = {}
        missing_sensors = []
        for zone in ("external", "internal"):
            sensor = by_zone.get(zone)
            if not sensor or current - parse_time(sensor["collected_at"]) > max_age:
                missing_sensors.append(zone)
                continue
            item = next((x for x in sensor["targets"] if x["id"] == target["id"]), None)
            probes = item["probes"] if item else []
            addresses[zone] = sorted({ip for p in probes for ip in p.get("addresses", [])})
            if any(p.get("reachable") for p in probes):
                actual.append(zone)
            expected_cidrs = target.get("expected_cidrs", {}).get(zone, [])
            if addresses[zone] and not in_expected_cidrs(addresses[zone], expected_cidrs):
                findings.append(finding("high", "address-drift", target["id"],
                                        "Адрес публикации вне ожидаемых CIDR в зоне " + zone,
                                        ", ".join(addresses[zone])))
        expected = target["expected_visibility"]
        unexpected = sorted(set(actual) - set(expected))
        missing = sorted((set(expected) - set(actual)) - set(missing_sensors))
        for zone in unexpected:
            findings.append(finding("critical" if target.get("criticality") == "critical" else "high",
                                    "unexpected-exposure", target["id"],
                                    "Незапланированная доступность из зоны " + zone))
        for zone in missing:
            findings.append(finding("medium", "missing-exposure", target["id"],
                                    "Ресурс недоступен из ожидаемой зоны " + zone))
        if missing_sensors:
            status = "unknown"
        elif unexpected:
            status = "unexpected_exposure"
        elif missing:
            status = "missing_exposure"
        else:
            status = "compliant"
        resources.append({
            "id": target["id"], "name": target["name"], "owner": target["owner"],
            "criticality": target.get("criticality", "medium"), "urls": target["urls"],
            "expected_visibility": expected, "actual_visibility": sorted(actual),
            "addresses": addresses, "missing_sensors": missing_sensors, "status": status,
        })
    findings.sort(key=lambda x: (-SEVERITY_ORDER.get(x["severity"], 0), x["resource"], x["rule"]))
    return {"schema_version": SCHEMA_VERSION, "kind": "aggregate", "generated_at": now_utc(),
            "resources": resources, "findings": findings,
            "sensors": {zone: by_zone[zone]["collected_at"] for zone in sorted(by_zone)}}


def write_csv(path, report):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["id", "name", "owner", "criticality", "status", "expected_visibility",
                         "actual_visibility", "external_addresses", "internal_addresses"])
        for row in report["resources"]:
            writer.writerow([row["id"], row["name"], row["owner"], row["criticality"], row["status"],
                             ",".join(row["expected_visibility"]), ",".join(row["actual_visibility"]),
                             ",".join(row["addresses"].get("external", [])),
                             ",".join(row["addresses"].get("internal", []))])


def render_html(report):
    esc = lambda value: html.escape(str(value))
    resource_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td><span class='{}'>{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            esc(r["id"]), esc(r["name"]), esc(r["owner"]), esc(r["status"]), esc(r["status"]),
            esc(", ".join(r["expected_visibility"]) or "—"), esc(", ".join(r["actual_visibility"]) or "—"),
            esc("; ".join(z + ": " + ", ".join(v) for z, v in r["addresses"].items()) or "—"))
        for r in report["resources"])
    finding_rows = "".join(
        "<tr><td><span class='{}'>{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            esc(f["severity"]), esc(f["severity"]), esc(f["resource"]), esc(f["rule"]),
            esc(f["message"]), esc(f.get("evidence", ""))) for f in report["findings"])
    counts = {s: sum(1 for f in report["findings"] if f["severity"] == s) for s in SEVERITY_ORDER}
    cards = "".join("<div class='card'><b>{}</b><strong>{}</strong></div>".format(esc(s), counts[s])
                    for s in ("critical", "high", "medium", "low", "info"))
    return """<!doctype html><html lang='ru'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>
<title>Аудит публикаций Nginx</title><style>
body{font:14px system-ui,sans-serif;margin:32px;color:#17202a;background:#f5f7fa}h1{margin-bottom:4px}small{color:#637083}
.cards{display:flex;gap:12px;margin:24px 0}.card{background:white;padding:14px 20px;border-radius:8px;box-shadow:0 1px 4px #ccd;min-width:90px}.card strong{display:block;font-size:24px}
table{width:100%%;border-collapse:collapse;background:white;margin:12px 0 28px}th,td{text-align:left;padding:9px;border-bottom:1px solid #e6e9ed;vertical-align:top}th{background:#edf1f5}
span{padding:2px 6px;border-radius:5px}.critical,.unexpected_exposure{background:#7f1d1d;color:white}.high{background:#dc2626;color:white}.medium,.missing_exposure{background:#f59e0b;color:#111}.low{background:#fde68a}.info{background:#dbeafe}.compliant{background:#dcfce7}.unknown{background:#e5e7eb}</style>
<h1>Аудит публикаций Nginx</h1><small>Сформирован: %s · датчики: %s</small><div class='cards'>%s</div>
<h2>Ресурсы</h2><table><thead><tr><th>ID</th><th>Ресурс</th><th>Владелец</th><th>Статус</th><th>Ожидалось</th><th>Фактически</th><th>Адреса</th></tr></thead><tbody>%s</tbody></table>
<h2>Находки</h2><table><thead><tr><th>Уровень</th><th>Ресурс</th><th>Правило</th><th>Описание</th><th>Свидетельство</th></tr></thead><tbody>%s</tbody></table></html>""" % (
        esc(report["generated_at"]), esc(", ".join(k + "=" + v for k, v in report["sensors"].items())), cards, resource_rows, finding_rows)


def aggregate(args):
    inventory = validate_inventory(read_json(args.inventory))
    sensors = [read_json(path) for path in args.input]
    nginx_reports = [read_json(path) for path in args.nginx_input]
    report = aggregate_data(inventory, sensors, nginx_reports)
    os.makedirs(args.output, exist_ok=True)
    atomic_json(os.path.join(args.output, "report.json"), report)
    write_csv(os.path.join(args.output, "summary.csv"), report)
    with open(os.path.join(args.output, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(report))
    if any(SEVERITY_ORDER.get(f["severity"], 0) >= SEVERITY_ORDER[args.fail_on] for f in report["findings"]):
        return 2
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    targets = subs.add_parser("targets")
    targets.add_argument("--inventory", required=True)
    targets.add_argument("--output", required=True)
    targets.set_defaults(func=emit_targets)
    collect_p = subs.add_parser("collect")
    collect_p.add_argument("--zone", choices=("external", "internal"), required=True)
    collect_p.add_argument("--inventory", required=True)
    collect_p.add_argument("--output", required=True)
    collect_p.add_argument("--timeout", type=float, default=8)
    collect_p.set_defaults(func=collect)
    enrich_p = subs.add_parser("enrich")
    enrich_p.add_argument("--sensor", required=True)
    enrich_p.add_argument("--directory", required=True)
    enrich_p.set_defaults(func=enrich)
    nginx_p = subs.add_parser("nginx-config")
    nginx_p.add_argument("--source", required=True)
    nginx_p.add_argument("--output", required=True)
    nginx_p.set_defaults(func=nginx_config)
    aggregate_p = subs.add_parser("aggregate")
    aggregate_p.add_argument("--inventory", required=True)
    aggregate_p.add_argument("--input", action="append", default=[], required=True)
    aggregate_p.add_argument("--nginx-input", action="append", default=[])
    aggregate_p.add_argument("--output", required=True)
    aggregate_p.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default="high")
    aggregate_p.set_defaults(func=aggregate)
    return parser


def main():
    args = build_parser().parse_args()
    try:
        result = args.func(args)
        return int(result or 0)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
