"""Generate a complete, Cyrillic-safe PDF representation of an NGINX Scope report."""

import html
import io
import os
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate, Paragraph,
    Preformatted, Spacer, Table, TableStyle,
)


INK = colors.HexColor("#12211c")
GREEN = colors.HexColor("#0c5b40")
PALE = colors.HexColor("#eef5ef")
LINE = colors.HexColor("#d8dfd9")
MUTED = colors.HexColor("#687870")
RED = colors.HexColor("#a9342d")
AMBER = colors.HexColor("#a86919")
BLUE = colors.HexColor("#326982")


def _font_paths():
    custom = os.environ.get("PDF_FONT_DIR")
    candidates = [
        Path(custom) if custom else None,
        Path("/usr/share/fonts/truetype/dejavu"),
        Path("/usr/share/fonts/dejavu"),
        Path("/Library/Fonts"),
        Path("/System/Library/Fonts/Supplemental"),
        Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/libreoffice-headless/libreoffice/LibreOfficeDev.app/Contents/Resources/fonts/truetype",
    ]
    for directory in candidates:
        if not directory:
            continue
        regular = directory / "DejaVuSans.ttf"
        bold = directory / "DejaVuSans-Bold.ttf"
        mono = directory / "DejaVuSansMono.ttf"
        if regular.exists() and bold.exists():
            return regular, bold, mono if mono.exists() else regular
    raise RuntimeError("Не найдены шрифты DejaVu Sans; установите пакет fonts-dejavu-core")


def _register_fonts():
    if "ScopeSans" in pdfmetrics.getRegisteredFontNames():
        return
    regular, bold, mono = _font_paths()
    pdfmetrics.registerFont(TTFont("ScopeSans", str(regular)))
    pdfmetrics.registerFont(TTFont("ScopeSans-Bold", str(bold)))
    pdfmetrics.registerFont(TTFont("ScopeMono", str(mono)))
    pdfmetrics.registerFontFamily("ScopeSans", normal="ScopeSans", bold="ScopeSans-Bold")


def _text(value):
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    return html.escape(str(value if value not in (None, "") else "-"))


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("ScopeTitle", parent=base["Title"], fontName="ScopeSans-Bold", fontSize=25,
                                leading=30, textColor=INK, alignment=TA_CENTER, spaceAfter=8),
        "subtitle": ParagraphStyle("ScopeSubtitle", parent=base["Normal"], fontName="ScopeSans", fontSize=9,
                                   leading=13, textColor=MUTED, alignment=TA_CENTER, spaceAfter=16),
        "h1": ParagraphStyle("ScopeH1", parent=base["Heading1"], fontName="ScopeSans-Bold", fontSize=16,
                             leading=20, textColor=GREEN, spaceBefore=8, spaceAfter=10),
        "h2": ParagraphStyle("ScopeH2", parent=base["Heading2"], fontName="ScopeSans-Bold", fontSize=12,
                             leading=16, textColor=INK, spaceBefore=8, spaceAfter=6),
        "h3": ParagraphStyle("ScopeH3", parent=base["Heading3"], fontName="ScopeSans-Bold", fontSize=10,
                             leading=14, textColor=GREEN, spaceBefore=5, spaceAfter=4),
        "body": ParagraphStyle("ScopeBody", parent=base["BodyText"], fontName="ScopeSans", fontSize=8.5,
                               leading=12, textColor=INK, spaceAfter=5),
        "small": ParagraphStyle("ScopeSmall", parent=base["BodyText"], fontName="ScopeSans", fontSize=7,
                                leading=10, textColor=MUTED),
        "code": ParagraphStyle("ScopeCode", parent=base["Code"], fontName="ScopeMono", fontSize=6.3,
                               leading=8.3, textColor=colors.HexColor("#e5eee8"), leftIndent=0),
        "finding": ParagraphStyle("ScopeFinding", parent=base["BodyText"], fontName="ScopeSans", fontSize=8,
                                  leading=11, textColor=INK),
        "severity": ParagraphStyle("ScopeSeverity", parent=base["BodyText"], fontName="ScopeSans-Bold", fontSize=5.8,
                                   leading=7, textColor=colors.white, alignment=TA_CENTER),
    }


def _page(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
    canvas.setFont("ScopeSans", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "NGINX Scope - конфигурационный аудит")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Страница {doc.page}")
    canvas.restoreState()


def _severity_color(severity):
    return {"critical": RED, "high": RED, "medium": AMBER, "low": BLUE}.get(severity, MUTED)


def _section_banner(title, styles):
    table = Table([[Paragraph(_text(title), styles["h1"])]], colWidths=[174 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE), ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return table


def _finding_card(item, styles):
    severity = item.get("severity", "info")
    severity_label = {"critical": "КРИТИЧЕСКИЙ", "high": "ВЫСОКИЙ", "medium": "СРЕДНИЙ", "low": "НИЗКИЙ", "info": "ИНФО"}.get(severity, severity.upper())
    content = [
        Paragraph(f"<b>{_text(item.get('message'))}</b>", styles["finding"]),
        Paragraph(f"Рекомендация: {_text(item.get('recommendation'))}", styles["finding"]),
        Paragraph(f"Правило: {_text(item.get('rule'))} | Объект: {_text(item.get('resource'))} | Контроль: {_text(item.get('control'))}", styles["small"]),
    ]
    if item.get("evidence"):
        content.append(Paragraph(f"Свидетельство: {_text(item['evidence'])}", styles["small"]))
    table = Table([[Paragraph(_text(severity_label), styles["severity"]), content]], colWidths=[22 * mm, 150 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), _severity_color(severity)),
        ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _meta_table(rows, styles):
    data = [[Paragraph(f"<b>{_text(name)}</b>", styles["small"]), Paragraph(_text(value), styles["body"])]
            for name, value in rows]
    table = Table(data, colWidths=[38 * mm, 134 * mm], repeatRows=0)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), PALE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _code_block(content, styles):
    pre = Preformatted(content or "", styles["code"], maxLineLength=105, splitChars=" /;")
    table = Table([[pre]], colWidths=[172 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), INK), ("BOX", (0, 0), (-1, -1), 0.5, INK),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def generate_pdf_report(report):
    _register_fonts()
    styles = _styles()
    output = io.BytesIO()
    doc = BaseDocTemplate(output, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                          topMargin=17 * mm, bottomMargin=20 * mm, title="NGINX Scope - полный отчёт")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal")
    doc.addPageTemplates([PageTemplate(id="report", frames=frame, onPage=_page)])
    story = [
        Paragraph("NGINX Scope", styles["title"]),
        Paragraph("Полный отчёт по конфигурации, публикациям и областям видимости", styles["subtitle"]),
        _meta_table([
            ("Сформирован", report.get("generated_at")), ("Оценка", f"{report.get('score', 0)}/100"),
            ("Публикаций", len(report.get("publications", []))), ("Ресурсов", len(report.get("resources", []))),
            ("Конфиденциальность", report.get("privacy")),
        ], styles), Spacer(1, 6 * mm),
        _section_banner("1. Сводка", styles), Spacer(1, 3 * mm),
    ]
    summary = report.get("summary", {})
    summary_data = [[Paragraph(f"<b>{name}</b>", styles["small"]), Paragraph(str(summary.get(key, 0)), styles["h2"])]
                    for name, key in (("Критические", "critical"), ("Высокие", "high"), ("Средние", "medium"), ("Низкие", "low"))]
    summary_table = Table([summary_data], colWidths=[43 * mm] * 4)
    summary_table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
                                       ("BACKGROUND", (0, 0), (-1, -1), PALE),
                                       ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                                       ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.extend([summary_table, Spacer(1, 5 * mm), _section_banner("2. Замечания и рекомендации", styles), Spacer(1, 3 * mm)])
    findings = report.get("findings", [])
    if findings:
        for item in findings:
            story.extend([_finding_card(item, styles), Spacer(1, 2 * mm)])
    else:
        story.append(Paragraph("Замечаний не найдено.", styles["body"]))

    story.extend([PageBreak(), _section_banner("3. Публикации", styles), Spacer(1, 3 * mm)])
    for index, publication in enumerate(report.get("publications", []), 1):
        names = ", ".join(publication.get("server_names", []))
        story.append(Paragraph(f"3.{index}. {_text(names)}", styles["h2"]))
        brief = publication.get("summary", {})
        brief_table = Table([[Paragraph(f"<b>Краткая справка</b><br/>{_text(brief.get('text'))}", styles["body"])]], colWidths=[172 * mm])
        brief_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PALE), ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                                         ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                         ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
        story.extend([brief_table, Spacer(1, 2 * mm), _meta_table([
            ("Тип", publication.get("publication_type")), ("Listen", publication.get("listen")),
            ("TLS", "включён" if publication.get("tls") else "не включён"),
            ("Потенциальная зона", publication.get("declared_visibility")),
            ("Фактическая зона", publication.get("actual_visibility") or "нет данных датчиков"),
            ("Адреса", publication.get("addresses")), ("Upstream", publication.get("upstreams") or "не найден"),
            ("Оценка", f"{publication.get('score', 0)}/100"),
        ], styles), Spacer(1, 2 * mm)])
        for setting in publication.get("setting_explanations", []):
            story.append(Paragraph(f"<b>{_text(setting.get('setting'))}: {_text(setting.get('value'))}</b> - {_text(setting.get('meaning'))} {_text(setting.get('impact'))}", styles["body"]))
        if publication.get("findings"):
            story.append(Paragraph("Замечания публикации", styles["h3"]))
            for item in publication["findings"]:
                story.extend([_finding_card(item, styles), Spacer(1, 1.5 * mm)])
        if publication.get("locations"):
            story.append(Paragraph("Пояснения location", styles["h3"]))
            for location in publication["locations"]:
                explanation = location.get("explanation", {})
                block = [Paragraph(f"<b>location {_text(location.get('path'))}</b> - {_text(explanation.get('match_type'))}", styles["body"]),
                         Paragraph(_text(explanation.get("matching")), styles["body"])]
                for directive in explanation.get("directives", []):
                    block.append(Paragraph(f"<b>{_text(directive.get('name'))} {_text(directive.get('value'))}</b>: {_text(directive.get('title'))}. {_text(directive.get('impact'))}", styles["small"]))
                story.append(KeepTogether(block))
                story.append(_code_block(location.get("config_excerpt", ""), styles))
                story.append(Spacer(1, 2 * mm))
        story.append(Paragraph("Фрагмент server", styles["h3"]))
        story.append(_code_block(publication.get("config_excerpt", ""), styles))
        story.append(Spacer(1, 5 * mm))

    story.extend([PageBreak(), _section_banner("4. Области видимости", styles), Spacer(1, 3 * mm)])
    resources = report.get("resources", [])
    if resources:
        data = [[Paragraph(f"<b>{name}</b>", styles["small"]) for name in ("Ресурс", "Ожидалось", "Фактически", "Адреса", "Статус")]]
        for resource in resources:
            data.append([Paragraph(_text(resource.get("name")), styles["small"]), Paragraph(_text(resource.get("expected_visibility")), styles["small"]),
                         Paragraph(_text(resource.get("actual_visibility")), styles["small"]), Paragraph(_text(resource.get("addresses")), styles["small"]),
                         Paragraph(_text(resource.get("status")), styles["small"])])
        table = Table(data, colWidths=[40 * mm, 28 * mm, 28 * mm, 50 * mm, 27 * mm], repeatRows=1)
        table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE), ("BACKGROUND", (0, 0), (-1, 0), INK),
                                   ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                                   ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        story.append(table)
    else:
        story.append(Paragraph("Данные внешнего и внутреннего датчиков не приложены.", styles["body"]))

    story.extend([Spacer(1, 6 * mm), _section_banner("5. Сравнение с эталоном", styles), Spacer(1, 3 * mm)])
    comparison = report.get("comparison", {})
    story.append(_meta_table([("Статус", comparison.get("status")), ("Добавлено", len(comparison.get("added", []))),
                              ("Удалено", len(comparison.get("removed", []))), ("Изменено", len(comparison.get("modified", []))),
                              ("Без изменений", comparison.get("unchanged", 0))], styles))
    for item in comparison.get("modified", []):
        story.append(Paragraph(f"<b>{_text(item.get('server_names'))}</b>", styles["h3"]))
        for change in item.get("changes", []):
            story.append(Paragraph(f"{_text(change.get('field'))}: {_text(change.get('before'))} -> {_text(change.get('after'))}", styles["small"]))

    story.extend([Spacer(1, 6 * mm), _section_banner("6. Методическая основа и ограничения", styles), Spacer(1, 3 * mm)])
    for source in report.get("methodology", []):
        story.append(Paragraph(f"• {_text(source)}", styles["body"]))
    story.append(Paragraph("Отчёт является результатом автоматизированного технического контроля и не заменяет аттестацию, модель угроз, проверку владельцем ресурса и анализ компенсирующих мер.", styles["body"]))
    doc.build(story)
    return output.getvalue()
