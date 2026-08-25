#!/usr/bin/env python3
"""Nginx publication visibility and safe misconfiguration audit."""

import argparse
import csv
import datetime as dt
import html
import hashlib
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

SECURITY_HEADER_NAMES = {name.lower() for name in SECURITY_HEADERS}
REQUEST_CONTROLLED_VARIABLE = re.compile(
    r"\$(?:http_[A-Za-z0-9_]+|arg_[A-Za-z0-9_]+|cookie_[A-Za-z0-9_]+|request_uri|uri|host)",
    re.I,
)

RULE_REFERENCES = {
    "publication-dynamic-upstream-ssrf": [{"title": "Gixy: SSRF", "url": "https://github.com/yandex/gixy/blob/master/docs/en/plugins/ssrf.md"}],
    "publication-host-header-spoofing": [{"title": "Gixy: Host spoofing", "url": "https://github.com/yandex/gixy/blob/master/docs/en/plugins/hostspoofing.md"}],
    "publication-http-splitting": [{"title": "Gixy: HTTP splitting", "url": "https://github.com/yandex/gixy/blob/master/docs/en/plugins/httpsplitting.md"}],
    "publication-add-header-shadow": [{"title": "NGINX: add_header inheritance", "url": "https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header"}],
    "publication-alias-traversal": [{"title": "Gixy: alias traversal", "url": "https://github.com/yandex/gixy/blob/master/docs/en/plugins/aliastraversal.md"}],
    "publication-incomplete-acl": [{"title": "NGINX: access module", "url": "https://nginx.org/en/docs/http/ngx_http_access_module.html"}],
    "publication-unsafe-valid-referers": [{"title": "Gixy: valid_referers", "url": "https://github.com/yandex/gixy/blob/master/docs/en/plugins/validreferers.md"}],
}

REMEDIATIONS = {
    "nginx-version-disclosure": "Добавьте server_tokens off; в контекст http и проверьте, что upstream не раскрывает свою версию.",
    "nginx-server-tokens": "Добавьте server_tokens off; в контекст http.",
    "nginx-old-tls": "Оставьте только ssl_protocols TLSv1.2 TLSv1.3; и проверьте совместимость клиентов.",
    "nginx-tls-policy-missing": "Явно задайте ssl_protocols TLSv1.2 TLSv1.3; в контексте http.",
    "nginx-autoindex": "Отключите листинг директивой autoindex off; и публикуйте только необходимые файлы.",
    "nginx-open-status": "Ограничьте location со stub_status: allow <CIDR мониторинга>; deny all; либо слушайте отдельный внутренний интерфейс.",
    "nginx-hsts": "В HTTPS-сервере добавьте Strict-Transport-Security с always. includeSubDomains/preload включайте только после проверки всех поддоменов.",
    "nginx-header-x-content-type-options": "Добавьте add_header X-Content-Type-Options \"nosniff\" always;.",
    "nginx-header-content-security-policy": "Сформируйте CSP по фактическим источникам приложения; начните с режима Content-Security-Policy-Report-Only.",
    "nginx-header-referrer-policy": "Добавьте add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;.",
    "nginx-header-permissions-policy": "Запретите неиспользуемые API, например add_header Permissions-Policy \"geolocation=(), camera=(), microphone=()\" always;.",
    "nginx-alias-traversal": "Используйте согласованные завершающие / в location и alias либо замените alias на root; отдельно проверьте нормализацию URI.",
    "nginx-no-default-server": "Добавьте отдельный default_server с server_name _; и return 444;, чтобы неизвестные Host не попадали в рабочий виртуальный хост.",
    "unsafe-cors": "Не сочетайте Access-Control-Allow-Origin: * с credentials; задайте точный allowlist доверенных origin.",
    "address-drift": "Сверьте DNS/LB/NAT с утверждёнными CIDR и обновите публикацию либо согласованный реестр после проверки владельцем.",
    "unexpected-exposure": "Закройте маршрут, listener или правило firewall из лишней зоны и повторите проверку соответствующим датчиком.",
    "missing-exposure": "Проверьте DNS, listener, маршрут и firewall требуемой зоны, затем повторите проверку датчиком.",
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
    recommendation = REMEDIATIONS.get(rule)
    if recommendation is None and rule.startswith("missing-header-"):
        recommendation = "Добавьте отсутствующий защитный HTTP-заголовок с директивой add_header и параметром always; значение проверьте по модели приложения."
    if recommendation is None and rule.startswith("testssl:"):
        recommendation = "Исправьте TLS-настройку по выводу testssl.sh, проверьте совместимость клиентов и повторите сканирование."
    if recommendation is None and rule.startswith("zap:"):
        recommendation = "Подтвердите замечание OWASP ZAP, устраните его в приложении или reverse proxy и выполните повторную проверку."
    if recommendation is None:
        recommendation = "Подтвердите отклонение владельцем ресурса, устраните первопричину и выполните повторную проверку."
    value["recommendation"] = recommendation
    if rule in RULE_REFERENCES:
        value["references"] = RULE_REFERENCES[rule]
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


def _named_block_ranges(content, name):
    """Return ranges for named Nginx blocks, ignoring comments and quoted braces."""
    starts = {match.end() - 1: match.start() for match in re.finditer(
        r"\b" + re.escape(name) + r"\b[^\{;]*\{", content, re.I
    )}
    stack = []
    ranges = []
    quoted = None
    escaped = False
    comment = False
    for index, char in enumerate(content):
        if comment:
            if char == "\n":
                comment = False
            continue
        if quoted:
            if char == quoted and not escaped:
                quoted = None
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
            continue
        if char == "#":
            comment = True
        elif char in {'"', "'"}:
            quoted = char
        elif char == "{":
            stack.append((index, starts.get(index)))
        elif char == "}" and stack:
            opening, named_start = stack.pop()
            if named_start is not None:
                ranges.append((named_start, opening, index + 1))
    return sorted(ranges)


def _mask_named_blocks(content, name):
    """Blank nested named blocks while preserving offsets and line numbers."""
    masked = list(content)
    for start, _, end in _named_block_ranges(content, name):
        for index in range(start, end):
            if masked[index] != "\n":
                masked[index] = " "
    return "".join(masked)


def _header_names(values):
    return {value.split()[0].lower() for value in values if value.split()}


def build_corrected_nginx_config(content):
    """Apply conservative hardening and return config plus changes requiring an owner."""
    fixed = content.replace("\r\n", "\n").replace("\r", "\n")
    fixed = re.sub(r"\bserver_tokens\s+[^;]+;", "server_tokens off;", fixed, flags=re.I)
    fixed = re.sub(r"\bssl_protocols\s+[^;]+;", "ssl_protocols TLSv1.2 TLSv1.3;", fixed, flags=re.I)
    fixed = re.sub(r"\bautoindex\s+on\s*;", "autoindex off;", fixed, flags=re.I)
    clean = "\n".join(strip_comments(line) for line in fixed.splitlines())
    http_ranges = _named_block_ranges(fixed, "http")
    applied = []
    manual = []

    if http_ranges:
        _, http_open, _ = http_ranges[0]
        directives = []
        if not re.search(r"\bserver_tokens\s+off\s*;", clean, re.I):
            directives.append("    server_tokens off;")
        if not re.search(r"\bssl_protocols\s+[^;]*TLSv1\.2[^;]*TLSv1\.3", clean, re.I):
            directives.append("    ssl_protocols TLSv1.2 TLSv1.3;")
        headers = (
            ("X-Content-Type-Options", '"nosniff"'),
            ("Referrer-Policy", '"strict-origin-when-cross-origin"'),
            ("Permissions-Policy", '"geolocation=(), camera=(), microphone=()"'),
        )
        for header, value in headers:
            if not re.search(r"\badd_header\s+" + re.escape(header) + r"\b", clean, re.I):
                directives.append(f"    add_header {header} {value} always;")
        if directives:
            banner = "\n    # NGINX Scope: безопасные автоматические исправления; проверьте nginx -t.\n"
            fixed = fixed[:http_open + 1] + banner + "\n".join(directives) + "\n" + fixed[http_open + 1:]
            applied.extend(directive.strip() for directive in directives)
    else:
        manual.append("Не найден блок http: автоматическая вставка общих директив пропущена.")

    clean = "\n".join(strip_comments(line) for line in fixed.splitlines())
    if re.search(r"\bstub_status\s*;", clean) and not re.search(r"\ballow\s+(?:127\.0\.0\.1|::1|unix:)", clean):
        manual.append("Укажите доверенный CIDR мониторинга для stub_status и завершите allowlist директивой deny all;.")
    if re.search(r"location\s+[^\{]*\.\.?[^\{]*\{[^}]*\balias\s+", clean, re.S):
        manual.append("Проверьте найденную пару location/alias вручную: автоматическая смена путей может нарушить маршрутизацию.")
    if not re.search(r"\badd_header\s+Content-Security-Policy\b", clean, re.I):
        manual.append("Настройте Content-Security-Policy по реальным источникам приложения, сначала в режиме Report-Only.")

    for _, opening, end in reversed(_named_block_ranges(fixed, "server")):
        block = fixed[opening:end]
        block_clean = "\n".join(strip_comments(line) for line in block.splitlines())
        is_tls = bool(re.search(r"\blisten\s+[^;]*(?:443|\bssl\b)[^;]*;|\bssl_certificate\s+", block_clean, re.I))
        has_hsts = bool(re.search(r"\badd_header\s+Strict-Transport-Security\b", block_clean, re.I))
        additions = []
        if is_tls and not has_hsts:
            additions.append('        add_header Strict-Transport-Security "max-age=31536000" always;')
            applied.append('add_header Strict-Transport-Security "max-age=31536000" always;')
        # In Nginx versions without add_header_inherit merge, one server-level add_header
        # cancels inheritance of every add_header from http. Repeat the safe baseline.
        if is_tls or re.search(r"\badd_header\s+", block_clean, re.I):
            for header, value in (
                ("X-Content-Type-Options", '"nosniff"'),
                ("Referrer-Policy", '"strict-origin-when-cross-origin"'),
                ("Permissions-Policy", '"geolocation=(), camera=(), microphone=()"'),
            ):
                if not re.search(r"\badd_header\s+" + re.escape(header) + r"\b", block_clean, re.I):
                    additions.append(f"        add_header {header} {value} always;")
        if additions:
            directive = "\n        # NGINX Scope: явный набор заголовков для корректного наследования.\n" + "\n".join(additions) + "\n"
            fixed = fixed[:opening + 1] + directive + fixed[opening + 1:]

    # A location-level add_header normally replaces inherited add_header values.
    # Repeat only the conservative security baseline so the corrected config does
    # not lose headers after it is uploaded for a second audit.
    server_ranges = _named_block_ranges(fixed, "server")
    for _, opening, end in reversed(_named_block_ranges(fixed, "location")):
        location_block = fixed[opening:end]
        location_clean = "\n".join(strip_comments(line) for line in location_block.splitlines())
        if not re.search(r"\badd_header\s+", location_clean, re.I):
            continue
        parent = next((fixed[s_start:s_end] for s_start, _, s_end in server_ranges
                       if s_start <= opening and end <= s_end), "")
        parent_clean = "\n".join(strip_comments(line) for line in parent.splitlines())
        is_tls = bool(re.search(r"\blisten\s+[^;]*(?:443|\bssl\b)[^;]*;|\bssl_certificate\s+", parent_clean, re.I))
        additions = []
        headers = [
            ("X-Content-Type-Options", '"nosniff"'),
            ("Referrer-Policy", '"strict-origin-when-cross-origin"'),
            ("Permissions-Policy", '"geolocation=(), camera=(), microphone=()"'),
        ]
        if is_tls:
            headers.insert(0, ("Strict-Transport-Security", '"max-age=31536000"'))
        for header, value in headers:
            if not re.search(r"\badd_header\s+" + re.escape(header) + r"\b", location_clean, re.I):
                additions.append(f"            add_header {header} {value} always;")
        if additions:
            directive = "\n            # NGINX Scope: location не теряет защитные заголовки родителя.\n" + "\n".join(additions) + "\n"
            fixed = fixed[:opening + 1] + directive + fixed[opening + 1:]
            applied.extend(directive.strip() for directive in additions)

    clean = "\n".join(strip_comments(line) for line in fixed.splitlines())
    http_ranges = _named_block_ranges(fixed, "http")
    if http_ranges and not re.search(r"\blisten\s+[^;]*\bdefault_server\b", clean):
        _, _, http_end = http_ranges[0]
        catch_all = "\n    # NGINX Scope: неизвестные имена хостов не попадают в рабочие vhost.\n    server {\n        listen 80 default_server;\n        listen [::]:80 default_server;\n        server_name _;\n        return 444;\n    }\n"
        fixed = fixed[:http_end - 1] + catch_all + fixed[http_end - 1:]
        applied.append("HTTP default_server с return 444")

    return fixed, applied, manual


def _directive_values(content, name):
    clean = "\n".join(strip_comments(line) for line in content.splitlines())
    return [" ".join(match.group(1).split()) for match in re.finditer(
        r"(?:^|(?<=[;{}]))\s*" + re.escape(name) + r"\s+([^;]+);", clean, re.I | re.M
    )]


def _location_blocks(server_block):
    values = []
    for match in re.finditer(r"\blocation\s+([^\{]+)\{", server_block, re.I):
        opening = match.end() - 1
        depth = 0
        quoted = None
        escaped = False
        comment = False
        for index in range(opening, len(server_block)):
            char = server_block[index]
            if comment:
                if char == "\n":
                    comment = False
                continue
            if quoted:
                if char == quoted and not escaped:
                    quoted = None
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
                continue
            if char == "#":
                comment = True
            elif char in {'"', "'"}:
                quoted = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    excerpt = server_block[match.start():index + 1].strip()
                    values.append({
                        "path": " ".join(match.group(1).split()),
                        "config_excerpt": excerpt,
                        "explanation": explain_location(" ".join(match.group(1).split()), excerpt),
                    })
                    break
    return values


def explain_location(path, excerpt):
    """Explain matching semantics and operational impact of one location block."""
    if path.startswith("= "):
        match_type = "Точное совпадение"
        matching = "Срабатывает только для указанного URI и имеет наивысший приоритет."
    elif path.startswith("^~ "):
        match_type = "Приоритетный префикс"
        matching = "Выбирается по наиболее длинному префиксу; после совпадения регулярные location не проверяются."
    elif path.startswith("~* "):
        match_type = "Регулярное выражение без учёта регистра"
        matching = "Проверяется в порядке расположения среди regex-location; первое совпадение завершает поиск."
    elif path.startswith("~ "):
        match_type = "Регулярное выражение с учётом регистра"
        matching = "Проверяется в порядке расположения среди regex-location; первое совпадение завершает поиск."
    elif path.startswith("@"):
        match_type = "Именованный внутренний маршрут"
        matching = "Не выбирается напрямую по URI; используется внутренним перенаправлением, error_page или try_files."
    else:
        match_type = "Префиксный маршрут"
        matching = "Nginx запоминает наиболее длинный подходящий префикс, затем может проверить regex-location."

    directive_help = {
        "proxy_pass": ("Передача в reverse proxy", "Определяет upstream. Наличие URI и завершающего / меняет преобразование исходного URI."),
        "fastcgi_pass": ("Передача в FastCGI", "Направляет запрос FastCGI-приложению, часто PHP-FPM; критичны fastcgi_param и проверка существования файла."),
        "uwsgi_pass": ("Передача в uWSGI", "Направляет запрос uWSGI-приложению и определяет сетевую связь публикации."),
        "root": ("Корень файлов", "Путь к файлу строится добавлением URI к указанному каталогу."),
        "alias": ("Подмена файлового пути", "Заменяет совпавшую часть location; несогласованные завершающие / могут открыть неверный каталог."),
        "try_files": ("Выбор файла или fallback", "Последовательно проверяет файлы и выполняет внутреннее перенаправление на последний вариант."),
        "return": ("Немедленный ответ", "Сразу возвращает код, текст или redirect и прекращает обычную обработку запроса."),
        "rewrite": ("Изменение URI", "Переписывает URI или выполняет redirect; может запустить повторный поиск location."),
        "auth_basic": ("Basic-аутентификация", "Запрашивает логин и пароль; безопасна только поверх TLS."),
        "auth_request": ("Внешняя проверка доступа", "Разрешение определяется результатом служебного subrequest к сервису авторизации."),
        "allow": ("Разрешение по адресу", "Разрешает указанный IP/CIDR; правила allow/deny проверяются по порядку до первого совпадения."),
        "deny": ("Запрет по адресу", "Запрещает указанный IP/CIDR; deny all обычно завершает allowlist."),
        "limit_req": ("Ограничение частоты", "Сдерживает частоту запросов и влияет на устойчивость к перегрузке и подбору."),
        "limit_conn": ("Ограничение соединений", "Ограничивает число одновременных соединений для заданного ключа."),
        "client_max_body_size": ("Максимальный размер запроса", "Ограничивает размер тела и загрузок; превышение приводит к HTTP 413."),
        "proxy_cache": ("Кэш reverse proxy", "Снижает нагрузку, но требует исключить персональные и авторизованные ответы."),
        "proxy_set_header": ("Заголовок для upstream", "Меняет сведения, которые получит приложение: Host, адрес клиента, протокол или авторизацию."),
        "add_header": ("Заголовок ответа", "Добавляет защитный или прикладной заголовок; наследование зависит от уровня и других add_header."),
        "internal": ("Только внутренний переход", "Прямой запрос клиента получит 404; маршрут доступен через внутреннее перенаправление."),
        "stub_status": ("Статус Nginx", "Показывает технические метрики и должен быть закрыт allowlist или аутентификацией."),
        "autoindex": ("Листинг каталога", "Значение on показывает список файлов при отсутствии index и может раскрыть содержимое."),
    }
    directives = []
    for name, (title, impact) in directive_help.items():
        values = _directive_values(excerpt, name)
        if name in {"internal", "stub_status"} and re.search(r"\b" + name + r"\s*;", excerpt, re.I):
            values = ["on"]
        for value in values:
            directives.append({"name": name, "value": value, "title": title, "impact": impact})
    if not directives:
        directives.append({
            "name": "inheritance", "value": "server/http", "title": "Наследуемая обработка",
            "impact": "В блоке нет явно распознанного обработчика; результат определяется унаследованными директивами и модулями Nginx.",
        })
    return {"match_type": match_type, "matching": matching, "directives": directives}


def build_publication_setting_explanations(publication):
    values = [
        {"setting": "listen", "value": ", ".join(publication.get("listen", [])),
         "meaning": "Адреса, порты и параметры сокета, на которых Nginx принимает соединения.",
         "impact": "Определяет потенциальную сетевую зону, HTTP/TLS и default_server."},
        {"setting": "server_name", "value": ", ".join(publication.get("server_names", [])),
         "meaning": "Имена Host/SNI, по которым выбирается виртуальный сервер.",
         "impact": "Wildcard или отсутствие точного имени расширяет поверхность публикации."},
        {"setting": "TLS", "value": "включён" if publication.get("tls") else "не включён",
         "meaning": "Шифрование и подтверждение подлинности соединения клиента.",
         "impact": "Для внешних и чувствительных ресурсов отсутствие TLS создаёт риск перехвата и подмены."},
        {"setting": "upstream", "value": ", ".join(publication.get("upstreams", [])) or "не найден",
         "meaning": "Приложение или файловый обработчик, которому передаётся запрос.",
         "impact": "Определяет внутреннюю сетевую связь, протокол и границу доверия."},
        {"setting": "журналирование", "value": "отключено" if any("access_log off" in x.get("evidence", "") for x in publication.get("findings", [])) else "явно не отключено",
         "meaning": "Регистрация HTTP-запросов и ошибок публикации.",
         "impact": "Необходимо для расследований, мониторинга и контроля событий безопасности."},
    ]
    return values


def _listen_visibility(listens):
    zones = set()
    basis = []
    for listen in listens:
        endpoint = listen.split()[0]
        if endpoint.startswith("unix:"):
            zones.add("internal")
            basis.append(f"{endpoint}: unix socket")
            continue
        host = endpoint
        if endpoint.isdigit():
            host = "0.0.0.0"
        elif endpoint.startswith("["):
            host = endpoint[1:endpoint.find("]")]
        elif endpoint.count(":") == 1:
            host = endpoint.rsplit(":", 1)[0]
        if host == "*":
            host = "0.0.0.0"
        elif host.lower() == "localhost":
            host = "127.0.0.1"
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            zones.add("unknown")
            basis.append(f"{endpoint}: имя/переменная требует проверки")
            continue
        if address.is_loopback:
            zones.add("local")
            basis.append(f"{endpoint}: только loopback")
        elif address.is_unspecified:
            zones.update(("internal", "external"))
            basis.append(f"{endpoint}: все интерфейсы, внешняя доступность зависит от firewall/LB")
        elif address.is_private or address.is_link_local:
            zones.add("internal")
            basis.append(f"{endpoint}: частный/локальный адрес")
        else:
            zones.add("external")
            basis.append(f"{endpoint}: публичный адрес")
    return sorted(zones), basis


def _publication_finding(severity, rule, publication_id, message, recommendation, control, evidence=None):
    item = finding(severity, rule, publication_id, message, evidence)
    item["recommendation"] = recommendation
    item["control"] = control
    return item


def build_publication_summary(publication):
    """Return a concise operator-facing brief for one publication."""
    if publication.get("publication_type") == "protective_default":
        return {
            "exposure": "Защитный системный listener",
            "purpose": "Отклонение запросов с неизвестным Host",
            "security": "Замечаний по этому блоку нет",
            "text": (
                f"Защитный catch-all на {', '.join(publication.get('listen', []))} отклоняет запросы "
                "с неизвестным именем хоста и не направляет их в приложение."
            ),
        }
    zone_names = {
        "external": "наружу", "internal": "во внутренний контур",
        "local": "только локально", "unknown": "в зону, требующую уточнения",
    }
    declared = [zone_names.get(zone, zone) for zone in publication.get("declared_visibility", [])]
    actual = [zone_names.get(zone, zone) for zone in publication.get("actual_visibility", [])]
    protocol = "HTTPS/TLS" if publication.get("tls") else "HTTP без TLS"
    locations = publication.get("locations", [])
    paths = ", ".join(item["path"] for item in locations[:3]) or "location не выделены"
    if len(locations) > 3:
        paths += f" и ещё {len(locations) - 3}"
    upstreams = publication.get("upstreams", [])
    route = ", ".join(upstreams[:2]) if upstreams else "локальная выдача или return"
    if len(upstreams) > 2:
        route += f" и ещё {len(upstreams) - 2}"
    findings = publication.get("findings", [])
    top_risks = "; ".join(item["message"] for item in findings[:2]) if findings else "локальных замечаний не найдено"
    actual_text = ", ".join(actual) if actual else "не подтверждена датчиками"
    exposure = ", ".join(declared) if declared else "не определена"
    names = ", ".join(publication.get("server_names", []))
    return {
        "exposure": f"Потенциально: {exposure}; фактически: {actual_text}",
        "purpose": f"{len(locations)} location ({paths}); назначение запросов: {route}",
        "security": f"Оценка {publication.get('score', 0)}/100; замечаний: {len(findings)}",
        "text": (
            f"{names}: {protocol} на {', '.join(publication.get('listen', []))}. "
            f"Потенциальная видимость — {exposure}, фактическая — {actual_text}. "
            f"Маршруты: {paths}; upstream: {route}. Кратко по рискам: {top_risks}."
        ),
    }


def extract_publications(content, source="uploaded-nginx-config"):
    """Build a per-server publication inventory and targeted security analytics."""
    publications = []
    http_parent_headers = set()
    http_inherit_merge = False
    http_ranges = _named_block_ranges(content, "http")
    if http_ranges:
        http_start, _, http_end = http_ranges[0]
        http_scope = _mask_named_blocks(content[http_start:http_end], "server")
        http_parent_headers = _header_names(_directive_values(http_scope, "add_header"))
        http_inherit_merge = bool(re.search(r"\badd_header_inherit\s+merge\s*;", http_scope, re.I))
    for number, (start, opening, end) in enumerate(_named_block_ranges(content, "server"), 1):
        block = content[start:end].strip()
        listens = _directive_values(block, "listen") or ["80 (implicit)"]
        names = []
        for value in _directive_values(block, "server_name"):
            names.extend(value.split())
        names = names or ["(не задан)"]
        upstreams = _directive_values(block, "proxy_pass") + _directive_values(block, "fastcgi_pass") + _directive_values(block, "uwsgi_pass")
        locations = _location_blocks(block)
        declared_zones, visibility_basis = _listen_visibility([x for x in listens if not x.endswith("(implicit)")])
        if listens == ["80 (implicit)"]:
            declared_zones = ["internal", "external"]
            visibility_basis = ["Неявный listen *:80: все интерфейсы"]
        identity_seed = "|".join(sorted(names)) + f"|position:{number}"
        publication_id = "pub-" + hashlib.sha256(identity_seed.encode("utf-8")).hexdigest()[:12]
        clean = "\n".join(strip_comments(line) for line in block.splitlines())
        tls = bool(re.search(r"\blisten\s+[^;]*(?:443|\bssl\b)[^;]*;|\bssl_certificate\s+", clean, re.I))
        external_possible = "external" in declared_zones
        reject_only = bool(
            any("default_server" in value for value in listens)
            and re.search(r"\breturn\s+(?:403|404|444)\s*;", clean, re.I)
            and not upstreams
        )
        findings = []

        # Gixy-derived data-flow checks. They intentionally target only
        # request-controlled variables in security-sensitive positions.
        for value in _directive_values(block, "proxy_pass"):
            match = re.match(r"https?://([^/]+)", value, re.I)
            authority = match.group(1) if match else ""
            if authority and REQUEST_CONTROLLED_VARIABLE.search(authority):
                findings.append(_publication_finding("high", "publication-dynamic-upstream-ssrf", publication_id,
                    "Адрес upstream управляется данными HTTP-запроса",
                    "Не подставляйте $host, $http_* или $arg_* в адрес proxy_pass. Выбирайте статический upstream через map с закрытым default и allowlist допустимых значений.",
                    "SSRF / КК", value))

        for value in _directive_values(block, "proxy_set_header"):
            if re.match(r"Host\s+\$http_host(?:\s|$)", value, re.I):
                findings.append(_publication_finding("high", "publication-host-header-spoofing", publication_id,
                    "В upstream передаётся непроверенный заголовок Host клиента",
                    "Замените $http_host на фиксированное имя upstream или на $host только при строгих server_name и защитном default_server.",
                    "ЗВТ.3 / Host", value))

        splitting_evidence = []
        for directive in ("add_header", "return", "rewrite"):
            for value in _directive_values(block, directive):
                sensitive_sink = (
                    directive == "add_header"
                    or (directive == "return" and re.match(r"30[1278]\s+", value))
                    or (directive == "rewrite" and re.search(r"\s(?:redirect|permanent)\s*$", value, re.I))
                )
                if sensitive_sink and REQUEST_CONTROLLED_VARIABLE.search(value):
                    splitting_evidence.append(f"{directive} {value}")
        if splitting_evidence:
            findings.append(_publication_finding("high", "publication-http-splitting", publication_id,
                "Данные запроса используются при формировании заголовка или перенаправления",
                "Не отражайте $http_*, $arg_*, $cookie_* и URI-переменные в add_header/redirect. Используйте строгий map/allowlist либо фиксированное значение.",
                "HTTP splitting / КК", "; ".join(splitting_evidence[:3])))

        server_scope = _mask_named_blocks(block, "location")
        server_headers = _header_names(_directive_values(server_scope, "add_header"))
        server_inherit_merge = http_inherit_merge or bool(re.search(r"\badd_header_inherit\s+merge\s*;", server_scope, re.I))
        parent_headers = (http_parent_headers | server_headers) if server_inherit_merge or not server_headers else server_headers
        parent_security_headers = parent_headers & SECURITY_HEADER_NAMES
        hidden_at_server = sorted((http_parent_headers & SECURITY_HEADER_NAMES) - server_headers)
        if server_headers and hidden_at_server and not server_inherit_merge:
            findings.append(_publication_finding("medium", "publication-add-header-shadow", publication_id,
                "Блок server перекрывает защитные заголовки уровня http",
                "Повторите в server весь требуемый набор add_header с always. add_header_inherit merge допустим только после подтверждения Nginx 1.29.3+.",
                "ЗВТ.3 / headers", ", ".join(hidden_at_server)))

        server_allows = _directive_values(server_scope, "allow")
        server_denies = [value.lower() for value in _directive_values(server_scope, "deny")]
        if server_allows and "all" not in server_denies:
            findings.append(_publication_finding("medium", "publication-incomplete-acl", publication_id,
                "В блоке server есть allow без завершающего deny all",
                "Завершите IP-allowlist директивой deny all и проверьте порядок правил. Если доступ должен быть открытым, удалите вводящий в заблуждение allow.",
                "УПД / ACL", ", ".join(server_allows)))
        for location in locations:
            location_clean = "\n".join(strip_comments(line) for line in location["config_excerpt"].splitlines())
            location_headers = _header_names(_directive_values(location_clean, "add_header"))
            inherit_merge = server_inherit_merge or bool(re.search(r"\badd_header_inherit\s+merge\s*;", location_clean, re.I))
            hidden_headers = sorted(parent_security_headers - location_headers)
            if location_headers and hidden_headers and not inherit_merge:
                findings.append(_publication_finding("medium", "publication-add-header-shadow", publication_id,
                    f"location {location['path']} перекрывает защитные заголовки родителя",
                    "Повторите в location весь требуемый набор add_header с always. add_header_inherit merge допустим только после подтверждения Nginx 1.29.3+.",
                    "ЗВТ.3 / headers", ", ".join(hidden_headers)))

            aliases = _directive_values(location_clean, "alias")
            match_type = location.get("explanation", {}).get("match_type")
            raw_path = re.sub(r"^(?:=|\^~)\s+", "", location["path"].strip())
            if match_type in {"Префиксный маршрут", "Точное совпадение", "Приоритетный префикс"}:
                for alias in aliases:
                    if raw_path and not raw_path.endswith("/") and alias.rstrip().endswith("/"):
                        findings.append(_publication_finding("high", "publication-alias-traversal", publication_id,
                            f"Несогласованные завершающие / в location {location['path']} и alias",
                            "Согласуйте завершающий / у префикса location и каталога alias либо используйте root; затем проверьте граничные URI и nginx -t.",
                            "Path traversal / КК", f"location {location['path']}; alias {alias}"))

            allows = _directive_values(location_clean, "allow")
            denies = [value.lower() for value in _directive_values(location_clean, "deny")]
            if allows and "all" not in denies:
                findings.append(_publication_finding("medium", "publication-incomplete-acl", publication_id,
                    f"В location {location['path']} есть allow без завершающего deny all",
                    "Завершите IP-allowlist директивой deny all и проверьте порядок правил. Если доступ должен быть открытым, удалите вводящий в заблуждение allow.",
                    "УПД / ACL", ", ".join(allows)))

        for value in _directive_values(block, "valid_referers"):
            tokens = {token.lower() for token in value.split()}
            unsafe = sorted(tokens & {"none", "blocked"})
            if unsafe:
                findings.append(_publication_finding("medium", "publication-unsafe-valid-referers", publication_id,
                    "Проверка Referer разрешает отсутствующее или нестандартное значение",
                    "Не используйте Referer как единственный механизм авторизации или CSRF-защиты. Удалите none/blocked, если запросы без доверенного Referer должны отклоняться.",
                    "CSRF / КК", " ".join(unsafe)))

        if external_possible and not tls and not reject_only:
            findings.append(_publication_finding("high", "publication-cleartext", publication_id,
                "Публикация потенциально доступна снаружи без TLS",
                "Настройте HTTPS, перенаправляйте HTTP на HTTPS и защитите ключи/сертификаты.", "ЗКС.1", ", ".join(listens)))
        if external_possible and not reject_only and any(name in {"_", "*", "(не задан)"} for name in names):
            findings.append(_publication_finding("medium", "publication-wildcard-name", publication_id,
                "Внешняя публикация принимает неопределённые имена хостов",
                "Укажите точные server_name и вынесите неизвестные Host в отдельный default_server с отказом.", "КК / ЗВТ.3"))
        if re.search(r"\baccess_log\s+off\s*;", clean, re.I):
            findings.append(_publication_finding("high", "publication-logging-disabled", publication_id,
                "Отключена регистрация HTTP-запросов",
                "Включите access_log в структурированном формате, ограничьте доступ и настройте передачу в SIEM.", "ЗВТ.4", "access_log off"))
        if re.search(r"\bproxy_ssl_verify\s+off\s*;", clean, re.I):
            findings.append(_publication_finding("high", "publication-upstream-tls-unverified", publication_id,
                "Отключена проверка сертификата HTTPS-upstream",
                "Включите proxy_ssl_verify on, задайте доверенный CA и корректный proxy_ssl_name.", "ЗКС.1", "proxy_ssl_verify off"))
        if any(value.startswith("https://") for value in upstreams) and not re.search(r"\bproxy_ssl_verify\s+on\s*;", clean, re.I):
            findings.append(_publication_finding("medium", "publication-upstream-verify-missing", publication_id,
                "Для HTTPS-upstream не найдена явная проверка сертификата",
                "Добавьте proxy_ssl_verify on, proxy_ssl_trusted_certificate и proxy_ssl_server_name on.", "ЗКС.1"))
        sensitive = any(re.search(r"(?:admin|status|metrics|debug|swagger|actuator)", loc["path"], re.I) for loc in locations)
        if external_possible and not reject_only and sensitive and not re.search(r"\b(?:allow|auth_request|auth_basic)\s+", clean, re.I):
            findings.append(_publication_finding("high", "publication-sensitive-endpoint-open", publication_id,
                "Служебный endpoint потенциально опубликован без ограничения доступа",
                "Ограничьте endpoint сетевым allowlist и сильной аутентификацией; предпочтительно вынесите во внутренний vhost.", "УПД / ЗВТ.2"))
        if external_possible and not reject_only and not re.search(r"\blimit_req\s+", clean, re.I):
            findings.append(_publication_finding("low", "publication-rate-limit-missing", publication_id,
                "Не найдено ограничение частоты запросов для внешней публикации",
                "Настройте limit_req_zone/limit_req по профилю нагрузки либо зафиксируйте эквивалентную защиту на WAF/LB.", "ЗОО.5"))
        if re.search(r"\bclient_max_body_size\s+0\s*;", clean, re.I):
            findings.append(_publication_finding("medium", "publication-unlimited-body", publication_id,
                "Размер тела запроса не ограничен",
                "Установите минимально необходимый client_max_body_size и согласуйте лимит с приложением.", "ЗОО.5", "client_max_body_size 0"))
        if external_possible and not reject_only and any(value.startswith("http://") for value in upstreams):
            findings.append(_publication_finding("low", "publication-cleartext-upstream", publication_id,
                "Данные передаются к upstream по HTTP",
                "Если upstream проходит через недоверенный сегмент, используйте HTTPS/mTLS; иначе документируйте границу доверия и сегментацию.", "ЗКС.1"))
        if re.search(r"\bproxy_pass\s+https?://[^\s/@]+:[^\s/@]+@", clean, re.I):
            findings.append(_publication_finding("critical", "publication-embedded-credentials", publication_id,
                "В proxy_pass обнаружены встроенные учётные данные",
                "Немедленно отзовите секрет, удалите его из конфигурации и истории, используйте защищённое хранилище секретов.", "ИАФ / КК"))
        if external_possible and not reject_only and upstreams and not re.search(r"\bproxy_(?:connect|read|send)_timeout\s+", clean, re.I):
            findings.append(_publication_finding("low", "publication-timeouts-missing", publication_id,
                "Не найдены явные timeout для reverse proxy",
                "Задайте минимально достаточные proxy_connect_timeout, proxy_read_timeout и proxy_send_timeout по SLA.", "ЗОО.5"))

        line_start = content.count("\n", 0, start) + 1
        for item in findings:
            item.setdefault("source", source)
            item.setdefault("line", line_start)
        score = max(0, 100 - sum({"critical": 24, "high": 14, "medium": 6, "low": 2}.get(x["severity"], 0) for x in findings))
        tracked_names = (
            "ssl_protocols", "ssl_ciphers", "access_log", "error_log", "client_max_body_size",
            "limit_req", "limit_conn", "auth_basic", "auth_request", "allow", "deny",
            "proxy_ssl_verify", "proxy_connect_timeout", "proxy_read_timeout", "proxy_send_timeout",
            "root", "alias", "return",
        )
        tracked_settings = {name: _directive_values(block, name) for name in tracked_names if _directive_values(block, name)}
        normalized_block = " ".join(clean.split())
        finding_counts = {severity: sum(1 for item in findings if item["severity"] == severity)
                          for severity in ("critical", "high", "medium", "low")}
        controls = sorted({item["control"] for item in findings})
        canonical = {
            "server_names": sorted(names), "listen": sorted(listens), "tls": tls,
            "publication_type": "protective_default" if reject_only else "application",
            "upstreams": sorted(upstreams), "locations": sorted(loc["path"] for loc in locations),
            "declared_visibility": declared_zones, "tracked_settings": tracked_settings,
            "semantic_digest": hashlib.sha256(normalized_block.encode("utf-8")).hexdigest(),
        }
        fingerprint = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        publication = {
            "id": publication_id, "number": number, "source": source,
            "line_start": line_start,
            "server_names": names, "listen": listens, "tls": tls,
            "publication_type": "protective_default" if reject_only else "application",
            "upstreams": upstreams, "locations": locations,
            "declared_visibility": declared_zones, "visibility_basis": visibility_basis,
            "actual_visibility": [], "addresses": {},
            "config_excerpt": block, "findings": findings, "score": score,
            "analytics": {
                "finding_counts": finding_counts, "controls_requiring_attention": controls,
                "attack_surface": {"locations": len(locations), "upstreams": len(upstreams)},
                "tracked_settings": tracked_settings,
            },
            "fingerprint": fingerprint, "canonical": canonical,
        }
        publication["summary"] = build_publication_summary(publication)
        publication["setting_explanations"] = build_publication_setting_explanations(publication)
        publications.append(publication)
    return publications


def correlate_publications(publications, inventory, resources):
    if not inventory:
        return publications
    resources_by_host = {}
    for target in inventory.get("targets", []):
        for url in target.get("urls", []):
            host = urllib.parse.urlsplit(url).hostname
            if host:
                resources_by_host.setdefault(host.lower(), []).append(target.get("id"))
    report_by_id = {item.get("id"): item for item in resources}
    for publication in publications:
        matched = set()
        catch_all = any(name in {"_", "*", "(не задан)"} for name in publication["server_names"])
        exact_names = {name.lower() for name in publication["server_names"] if not name.startswith("*.")}
        suffixes = [name[1:].lower() for name in publication["server_names"] if name.startswith("*.")]
        for host, ids in resources_by_host.items():
            if catch_all or host in exact_names or any(host.endswith(suffix) for suffix in suffixes):
                matched.update(ids)
        actual = set()
        addresses = {}
        for resource_id in matched:
            resource = report_by_id.get(resource_id, {})
            actual.update(resource.get("actual_visibility", []))
            for zone, values in resource.get("addresses", {}).items():
                addresses.setdefault(zone, set()).update(values)
        publication["resource_ids"] = sorted(matched)
        publication["actual_visibility"] = sorted(actual)
        publication["addresses"] = {zone: sorted(values) for zone, values in addresses.items()}
        publication["summary"] = build_publication_summary(publication)
    return publications


def build_publication_baseline(publications, source):
    records = [{"id": item["id"], "fingerprint": item["fingerprint"], "canonical": item["canonical"]}
               for item in publications]
    return {
        "schema_version": 1, "kind": "nginx-publication-baseline", "created_at": now_utc(),
        "source": source, "publications": records,
        "baseline_fingerprint": hashlib.sha256(json.dumps(records, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def compare_publication_baseline(publications, baseline):
    if not baseline:
        return {"status": "not_compared", "added": [], "removed": [], "modified": [], "unchanged": 0}
    if baseline.get("kind") != "nginx-publication-baseline" or baseline.get("schema_version") != 1:
        raise ValueError("неподдерживаемый формат эталона публикаций")
    old = {item["id"]: item for item in baseline.get("publications", [])}
    current = {item["id"]: item for item in publications}
    added = [current[key]["canonical"] for key in sorted(current.keys() - old.keys())]
    removed = [old[key]["canonical"] for key in sorted(old.keys() - current.keys())]
    modified = []
    unchanged = 0
    for key in sorted(current.keys() & old.keys()):
        if current[key]["fingerprint"] == old[key].get("fingerprint"):
            unchanged += 1
            continue
        before = old[key].get("canonical", {})
        after = current[key]["canonical"]
        fields = [{"field": field, "before": before.get(field), "after": after.get(field)}
                  for field in sorted(set(before) | set(after)) if before.get(field) != after.get(field)]
        modified.append({"id": key, "server_names": after.get("server_names", []), "changes": fields})
    status = "changed" if added or removed or modified else "unchanged"
    return {"status": status, "added": added, "removed": removed, "modified": modified, "unchanged": unchanged}


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
