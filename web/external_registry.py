"""Safe import of external DNAT publication registries from XLSX."""

import io
import ipaddress
import re
import zipfile

from openpyxl import load_workbook


REQUIRED_HEADERS = {
    "rule_id": {"id правила", "ид правила", "rule id"},
    "rule_type": {"тип", "type"},
    "source_interface": {"источник / интерфейс", "источник/интерфейс", "интерфейс"},
    "external_port": {"внешний порт", "external port"},
    "internal_ip": {"внутренний ip", "internal ip"},
    "internal_port": {"внутренний порт", "internal port"},
    "protocol": {"протокол", "protocol"},
}
MAX_REGISTRY_ROWS = 10_000
MAX_ZIP_MEMBERS = 500
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024


def _normalized(value):
    return " ".join(str(value or "").strip().lower().replace("ё", "е").split())


def _field_map(row):
    values = {_normalized(value): index for index, value in enumerate(row) if _normalized(value)}
    result = {}
    for field, aliases in REQUIRED_HEADERS.items():
        index = next((values[alias] for alias in aliases if alias in values), None)
        if index is None:
            return None
        result[field] = index
    return result


def _cell(row, index):
    return row[index] if index < len(row) else None


def _identifier(value):
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value or "").strip()


def _port(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if int(value) == value and 1 <= int(value) <= 65535:
            return int(value), None
        raise ValueError(f"порт вне диапазона: {value}")
    text = str(value or "").strip()
    if _normalized(text) in {"any", "любой", "все", "*"}:
        return "any", None
    try:
        address = str(ipaddress.ip_address(text))
        return "any", address
    except ValueError:
        pass
    if text.isdigit() and 1 <= int(text) <= 65535:
        return int(text), None
    raise ValueError(f"некорректный порт: {text or 'пусто'}")


def _external_network(value):
    text = str(value or "").strip()
    match = re.search(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:[/-](\d{1,2}))?(?![\d.])", text)
    if not match:
        return None
    candidate = match.group(1) + ("/" + match.group(2) if match.group(2) else "")
    try:
        return str(ipaddress.ip_network(candidate, strict=False)) if "/" in candidate else str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _validate_archive(raw):
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                raise ValueError("слишком много объектов внутри XLSX")
            if sum(item.file_size for item in members) > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("XLSX превышает безопасный распакованный размер")
            names = {item.filename.lower() for item in members}
            if any(name.endswith("vbaproject.bin") for name in names):
                raise ValueError("XLSX с макросами не поддерживается")
            if archive.testzip() is not None:
                raise ValueError("XLSX повреждён")
    except zipfile.BadZipFile as exc:
        raise ValueError("файл не является корректным XLSX") from exc


def parse_external_registry_xlsx(raw, filename="external-publications.xlsx"):
    _validate_archive(raw)
    try:
        workbook = load_workbook(io.BytesIO(raw), read_only=True, data_only=True, keep_links=False)
    except Exception as exc:
        raise ValueError("не удалось прочитать книгу XLSX") from exc
    try:
        selected = None
        for sheet in workbook.worksheets:
            for row_number, row in enumerate(sheet.iter_rows(min_row=1, max_row=20, values_only=True), 1):
                mapping = _field_map(row)
                if mapping:
                    selected = (sheet, row_number, mapping)
                    break
            if selected:
                break
        if not selected:
            expected = ", ".join(sorted(next(iter(value)) for value in REQUIRED_HEADERS.values()))
            raise ValueError("не найдена строка заголовков; обязательные колонки: " + expected)

        sheet, header_row, mapping = selected
        rules = []
        duplicates = 0
        seen = set()
        for row_number, row in enumerate(sheet.iter_rows(min_row=header_row + 1, values_only=True), header_row + 1):
            if not any(value not in (None, "") for value in row):
                continue
            if len(rules) >= MAX_REGISTRY_ROWS:
                raise ValueError(f"реестр содержит более {MAX_REGISTRY_ROWS} строк")
            rule_id = _identifier(_cell(row, mapping["rule_id"]))
            if not rule_id:
                raise ValueError(f"строка {row_number}: не указан ID правила")
            internal_ip = str(_cell(row, mapping["internal_ip"]) or "").strip()
            try:
                internal_ip = str(ipaddress.ip_address(internal_ip))
            except ValueError as exc:
                raise ValueError(f"строка {row_number}: некорректный внутренний IP") from exc
            external_port, external_address = _port(_cell(row, mapping["external_port"]))
            internal_port, _ = _port(_cell(row, mapping["internal_port"]))
            protocol = _normalized(_cell(row, mapping["protocol"]))
            protocol = {"6": "tcp", "17": "udp", "любой": "any", "все": "any", "*": "any"}.get(protocol, protocol)
            if protocol not in {"tcp", "udp", "any"}:
                raise ValueError(f"строка {row_number}: протокол должен быть tcp, udp или Any")
            source_interface = str(_cell(row, mapping["source_interface"]) or "").strip()
            item = {
                "rule_id": rule_id,
                "rule_type": str(_cell(row, mapping["rule_type"]) or "").strip().upper(),
                "source_interface": source_interface,
                "external_network": external_address or _external_network(source_interface),
                "external_port": external_port,
                "internal_ip": internal_ip,
                "internal_port": internal_port,
                "protocol": protocol,
                "sheet": sheet.title,
                "row": row_number,
            }
            signature = tuple(item[key] for key in (
                "rule_id", "rule_type", "source_interface", "external_port",
                "internal_ip", "internal_port", "protocol",
            ))
            if signature in seen:
                duplicates += 1
                continue
            seen.add(signature)
            rules.append(item)
        if not rules:
            raise ValueError("реестр не содержит правил публикации")
        return {
            "kind": "external-publication-registry",
            "source": filename,
            "sheet": sheet.title,
            "rules": rules,
            "duplicates_ignored": duplicates,
        }
    finally:
        workbook.close()
