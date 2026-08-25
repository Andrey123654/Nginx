import json
import os
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fastapi import Body, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from audit import (
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    aggregate_data,
    analyze_nginx_text,
    build_publication_baseline,
    build_corrected_nginx_config,
    compare_publication_baseline,
    correlate_publications,
    extract_publications,
    now_utc,
    validate_inventory,
)
from web.pdf_report import generate_pdf_report
from web.sarif_report import generate_sarif_report

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 5 * 1024 * 1024))
APP_VERSION = "1.5.0"
PUBLIC_ORIGIN = os.environ.get("PUBLIC_ORIGIN", "http://127.0.0.1:8080").rstrip("/")
if urlsplit(PUBLIC_ORIGIN).scheme not in {"http", "https"} or not urlsplit(PUBLIC_ORIGIN).hostname:
    raise RuntimeError("PUBLIC_ORIGIN must be an absolute http(s) origin")
ALLOWED_JSON_SUFFIXES = {".json"}

app = FastAPI(
    title="NGINX Scope",
    description="Аудит конфигураций Nginx и областей сетевой видимости",
    version="1.5.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Nginx-Scope-Version"] = APP_VERSION
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def upload_rejection(status_code, code, message, upload=None, hint=None):
    detail = {"code": code, "message": message}
    if upload is not None and upload.filename:
        detail["filename"] = Path(upload.filename).name[:160]
    if hint:
        detail["hint"] = hint
    return HTTPException(status_code=status_code, detail=detail)


async def read_upload(upload: UploadFile, allowed_suffixes=None, required=True, allow_no_suffix=False):
    if upload is None or not upload.filename:
        if required:
            raise upload_rejection(400, "file_missing", "Обязательный файл не передан",
                                   hint="Выберите файл конфигурации Nginx и повторите проверку")
        return None
    suffix = Path(upload.filename or "").suffix.lower()
    if allowed_suffixes is not None and suffix not in allowed_suffixes and not (allow_no_suffix and suffix == ""):
        raise upload_rejection(415, "unsupported_extension",
                               f"Недопустимое расширение: {suffix or 'без расширения'}", upload,
                               "Для inventory и датчиков используйте JSON-файл с расширением .json")
    chunks = []
    total = 0
    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise upload_rejection(413, "file_too_large",
                                   f"Размер файла превышает лимит {MAX_UPLOAD_BYTES // (1024 * 1024)} МБ", upload,
                                   "Уменьшите файл или согласованно увеличьте MAX_UPLOAD_BYTES и client_max_body_size")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if b"\x00" in raw:
        raise upload_rejection(415, "binary_file", "Файл содержит бинарные данные", upload,
                               "Загрузите текстовый nginx.conf или текстовый вывод nginx -T")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise upload_rejection(415, "invalid_encoding", "Файл невозможно прочитать как UTF-8", upload,
                               "Преобразуйте текст в кодировку UTF-8 и повторите проверку") from exc


def parse_json_payload(text, label):
    if text is None:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Некорректный JSON в {label}") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail=f"{label} должен содержать JSON-объект")
    return value


def score_for(findings):
    penalties = {"critical": 24, "high": 14, "medium": 6, "low": 2, "info": 0}
    return max(0, 100 - sum(penalties.get(item.get("severity", "info"), 0) for item in findings))


def build_report(config_findings, inventory=None, sensors=None, corrected_config=None,
                 applied_fixes=None, manual_actions=None, publications=None,
                 baseline=None, comparison=None):
    sensors = sensors or []
    resources = []
    findings = list(config_findings)
    sensor_times = {}
    if inventory is not None:
        try:
            inventory = validate_inventory(inventory)
            aggregate = aggregate_data(inventory, sensors, [])
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(status_code=422, detail="Ошибка inventory/датчиков: " + str(exc)) from exc
        resources = aggregate["resources"]
        findings.extend(aggregate["findings"])
        sensor_times = aggregate["sensors"]
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item.get("severity", "info"), 0), item.get("rule", "")))
    counts = {name: sum(1 for item in findings if item.get("severity") == name) for name in SEVERITY_ORDER}
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_utc(),
        "score": score_for(findings),
        "summary": counts,
        "findings": findings,
        "resources": resources,
        "sensors": sensor_times,
        "corrected_config": corrected_config,
        "applied_fixes": applied_fixes or [],
        "manual_actions": manual_actions or [],
        "publications": publications or [],
        "baseline": baseline,
        "comparison": comparison or {"status": "not_compared", "added": [], "removed": [], "modified": [], "unchanged": 0},
        "methodology": [
            "ФСТЭК России 12.04.2026: КК, ЗВТ.2-ЗВТ.4, ЗОО.5, ЗКС.1",
            "CIS NGINX Benchmark 3.0.0",
            "NIST SP 800-128",
            "OWASP Web Security Testing Guide",
            "Gixy и Gixy-Next: классы статических проверок конфигурации",
            "официальная документация Nginx и TLSRef",
        ],
        "privacy": "Исходный и исправленный конфиги возвращаются только в текущий ответ и не сохраняются на сервере",
    }


@app.get("/", include_in_schema=False)
async def index():
    markup = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(markup.replace("{{PUBLIC_ORIGIN}}", PUBLIC_ORIGIN))


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {
        "status": "ok",
        "version": APP_VERSION,
        "config_upload": "any UTF-8 text filename, max 5 MiB",
    }


@app.post("/api/export/pdf", include_in_schema=False)
async def export_pdf(report: dict = Body(...)):
    if report.get("schema_version") != SCHEMA_VERSION or not isinstance(report.get("publications", []), list):
        raise HTTPException(status_code=422, detail="Некорректный формат отчёта для экспорта PDF")
    if len(json.dumps(report, ensure_ascii=False)) > 16 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Отчёт слишком большой для экспорта PDF")
    try:
        content = generate_pdf_report(report)
    except (RuntimeError, ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=422, detail="Не удалось сформировать PDF: " + str(exc)) from exc
    return Response(content, media_type="application/pdf", headers={
        "Content-Disposition": 'attachment; filename="nginx-scope-report.pdf"',
        "Cache-Control": "no-store",
    })


@app.post("/api/export/sarif", include_in_schema=False)
async def export_sarif(report: dict = Body(...)):
    if report.get("schema_version") != SCHEMA_VERSION or not isinstance(report.get("findings", []), list):
        raise HTTPException(status_code=422, detail="Некорректный формат отчёта для экспорта SARIF")
    if len(json.dumps(report, ensure_ascii=False)) > 16 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Отчёт слишком большой для экспорта SARIF")
    content = generate_sarif_report(report)
    return Response(content, media_type="application/sarif+json", headers={
        "Content-Disposition": 'attachment; filename="nginx-scope-results.sarif"',
        "Cache-Control": "no-store",
    })


@app.post("/api/analyze", include_in_schema=False)
async def analyze(
    nginx_config: UploadFile = File(...),
    inventory: Optional[UploadFile] = File(None),
    external_sensor: Optional[UploadFile] = File(None),
    internal_sensor: Optional[UploadFile] = File(None),
    baseline: Optional[UploadFile] = File(None),
):
    config_text = await read_upload(nginx_config)
    inventory_text = await read_upload(inventory, ALLOWED_JSON_SUFFIXES, required=False)
    external_text = await read_upload(external_sensor, ALLOWED_JSON_SUFFIXES, required=False)
    internal_text = await read_upload(internal_sensor, ALLOWED_JSON_SUFFIXES, required=False)
    baseline_text = await read_upload(baseline, ALLOWED_JSON_SUFFIXES, required=False)
    source_name = Path(nginx_config.filename or "uploaded.conf").name[:160]
    config_findings = analyze_nginx_text(config_text, source_name)
    publications = extract_publications(config_text, source_name)
    config_findings.extend(item for publication in publications for item in publication["findings"])
    corrected_config, applied_fixes, manual_actions = build_corrected_nginx_config(config_text)
    inventory_data = parse_json_payload(inventory_text, "inventory")
    baseline_data = parse_json_payload(baseline_text, "эталоне")
    sensors = []
    for text, expected_zone in ((external_text, "external"), (internal_text, "internal")):
        sensor = parse_json_payload(text, f"датчике {expected_zone}")
        if sensor is None:
            continue
        if sensor.get("kind") != "sensor" or sensor.get("zone") != expected_zone:
            raise HTTPException(status_code=422, detail=f"Файл датчика должен иметь zone={expected_zone}")
        sensors.append(sensor)
    if sensors and inventory_data is None:
        raise HTTPException(status_code=422, detail="Для отчёта о видимости требуется inventory.json")
    report = build_report(config_findings, inventory_data, sensors, corrected_config,
                          applied_fixes, manual_actions)
    publications = correlate_publications(publications, inventory_data, report["resources"])
    try:
        comparison = compare_publication_baseline(publications, baseline_data)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="Ошибка эталона: " + str(exc)) from exc
    current_baseline = build_publication_baseline(publications, source_name)
    report["publications"] = publications
    report["baseline"] = current_baseline
    report["comparison"] = comparison
    return JSONResponse(report)
