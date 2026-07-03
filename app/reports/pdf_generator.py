from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


CHARCOAL = colors.HexColor("#15181b")
LIME = colors.HexColor("#b7ff3c")
SOFT = colors.HexColor("#d9dcdf")


def generate_scan_pdf(scan, metrics, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(output_path), pagesize=LETTER, rightMargin=0.6 * inch, leftMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SentinelTitle", fontName="Times-Bold", fontSize=22, textColor=CHARCOAL, spaceAfter=12))
    styles.add(ParagraphStyle(name="SentinelBody", fontName="Times-Roman", fontSize=10, leading=13, textColor=CHARCOAL))
    styles.add(ParagraphStyle(name="SentinelSmall", fontName="Times-Roman", fontSize=8, leading=10, textColor=colors.HexColor("#30363b")))
    story = [
        Paragraph("Sentinel Audit", styles["SentinelTitle"]),
        Paragraph("Educational Web Security Audit Report", styles["SentinelBody"]),
        Spacer(1, 0.15 * inch),
    ]
    summary_rows = [
        ["Target URL", _safe(scan.target_url)],
        ["Final URL", _safe(scan.final_url or "Not recorded")],
        ["Scan date", scan.started_at.strftime("%Y-%m-%d %H:%M UTC")],
        ["Profile", scan.scan_profile.title()],
        ["Security score", str(scan.security_score)],
        ["Risk level", scan.risk_level],
    ]
    story.append(_table(summary_rows))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(
        "Sentinel Audit performs limited, non-destructive configuration checks. "
        "This score is educational and is not an official certification, penetration test, or compliance result.",
        styles["SentinelBody"],
    ))
    story.append(Spacer(1, 0.15 * inch))
    counts = {
        "Passed": scan.count_status("passed"),
        "Warnings": scan.count_status("warning"),
        "Failed": scan.count_status("failed"),
        "Informational": scan.count_status("info"),
    }
    story.append(_table([[key, str(value)] for key, value in counts.items()]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Findings", styles["Heading2"]))
    for severity in ["critical", "high", "medium", "low", "info"]:
        grouped = [finding for finding in scan.findings if finding.severity == severity]
        if not grouped:
            continue
        story.append(Paragraph(severity.title(), styles["Heading3"]))
        for finding in grouped:
            story.append(Paragraph(_safe(finding.title), styles["Heading4"]))
            story.append(Paragraph(f"Status: {_safe(finding.status)} | Category: {_safe(finding.category)}", styles["SentinelSmall"]))
            story.append(Paragraph(_safe(finding.description), styles["SentinelBody"]))
            story.append(Paragraph(f"Evidence: {_safe(finding.evidence)}", styles["SentinelSmall"]))
            story.append(Paragraph(f"Recommendation: {_safe(finding.recommendation)}", styles["SentinelBody"]))
            story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph("Technical Details", styles["Heading2"]))
    tech_rows = [
        ["HTTP status", str(scan.http_status or "Unknown")],
        ["Response time", f"{scan.response_time or 0:.3f}s"],
        ["Redirect count", str(scan.redirect_count or 0)],
        ["Content type", metrics.get("content_type", "unknown")],
        ["Forms", metrics.get("form_count", "0")],
        ["Cookies", metrics.get("cookie_count", "0")],
        ["Headers checked", metrics.get("headers_checked", "0")],
        ["TLS expiry", metrics.get("tls_expiry", "Not recorded")],
    ]
    story.append(_table(tech_rows))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(
        "Educational disclaimer: this report does not replace a professional penetration test, compliance audit, or manual security assessment.",
        styles["SentinelSmall"],
    ))
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return output_path


def _table(rows):
    table = Table(rows, colWidths=[1.7 * inch, 5.2 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), CHARCOAL),
        ("TEXTCOLOR", (0, 0), (0, -1), LIME),
        ("TEXTCOLOR", (1, 0), (1, -1), CHARCOAL),
        ("GRID", (0, 0), (-1, -1), 0.25, SOFT),
        ("FONTNAME", (0, 0), (-1, -1), "Times-Roman"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Times-Roman", 8)
    canvas.setFillColor(colors.HexColor("#717980"))
    canvas.drawString(0.6 * inch, 0.4 * inch, "Sentinel Audit | Defensive educational checks only")
    canvas.drawRightString(7.9 * inch, 0.4 * inch, f"Page {doc.page}")
    canvas.restoreState()


def _safe(value):
    return str(value or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
