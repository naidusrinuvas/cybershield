"""
PDF Report Generator
Builds a professional PDF report for a single scan (or a full scan history)
using ReportLab, including the AI-generated analysis.
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
)

RISK_COLORS = {
    "High": colors.HexColor("#dc3545"),
    "Medium": colors.HexColor("#ffc107"),
    "Low": colors.HexColor("#198754"),
    "Unknown": colors.HexColor("#6c757d"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CSTitle", fontSize=22, leading=26, spaceAfter=6, textColor=colors.HexColor("#0d6efd")))
    styles.add(ParagraphStyle(name="CSHeading", fontSize=14, leading=18, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#10141c")))
    styles.add(ParagraphStyle(name="CSBody", fontSize=10.5, leading=15))
    return styles


def generate_single_scan_report(scan: dict, ai_analysis: dict, username: str, output_path: str) -> str:
    """
    scan: dict with keys scan_type, target, result, risk_level, date
    ai_analysis: dict with keys summary, risk_explanation, recommendations, source
    """
    styles = _styles()
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    story = []

    story.append(Paragraph("CyberShield Security Report", styles["CSTitle"]))
    story.append(Paragraph("AI-Powered Cyber Security Assessment Toolkit", styles["CSBody"]))
    story.append(Spacer(1, 0.5*cm))

    meta_table = Table([
        ["Generated on:", datetime.now().strftime("%Y-%m-%d %H:%M")],
        ["User:", username],
        ["Scan type:", scan["scan_type"]],
        ["Target:", scan["target"]],
        ["Scan date:", str(scan["date"])],
    ], colWidths=[4*cm, 11*cm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.grey),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Scan Result", styles["CSHeading"]))
    story.append(Paragraph(str(scan["result"]), styles["CSBody"]))

    risk = scan["risk_level"]
    risk_color = RISK_COLORS.get(risk, colors.grey)
    story.append(Spacer(1, 0.3*cm))
    risk_table = Table([[f"Risk Level: {risk}"]], colWidths=[15*cm])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), risk_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 12),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(risk_table)

    story.append(Paragraph("AI Summary", styles["CSHeading"]))
    story.append(Paragraph(ai_analysis["summary"], styles["CSBody"]))

    story.append(Paragraph("Risk Explanation", styles["CSHeading"]))
    story.append(Paragraph(ai_analysis["risk_explanation"], styles["CSBody"]))

    story.append(Paragraph("Recommendations", styles["CSHeading"]))
    rec_items = [ListItem(Paragraph(r, styles["CSBody"])) for r in ai_analysis["recommendations"]]
    story.append(ListFlowable(rec_items, bulletType="bullet"))

    story.append(Spacer(1, 1*cm))
    source_note = "Generated with AI analysis" if ai_analysis.get("source") == "ai" else "Generated with rule-based analysis engine"
    story.append(Paragraph(f"<i>{source_note}</i>", styles["CSBody"]))

    doc.build(story)
    return output_path


def generate_full_history_report(scans: list, username: str, output_path: str) -> str:
    """scans: list of scan dicts (scan_type, target, result, risk_level, date)."""
    styles = _styles()
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    story = []

    story.append(Paragraph("CyberShield Security Report", styles["CSTitle"]))
    story.append(Paragraph("Full Scan History Summary", styles["CSBody"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')} &mdash; User: {username}", styles["CSBody"]))
    story.append(Spacer(1, 0.5*cm))

    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for s in scans:
        risk_counts[s["risk_level"]] = risk_counts.get(s["risk_level"], 0) + 1

    summary_table = Table([
        ["Total Scans", "High Risk", "Medium Risk", "Low Risk"],
        [str(len(scans)), str(risk_counts.get("High", 0)), str(risk_counts.get("Medium", 0)), str(risk_counts.get("Low", 0))],
    ], colWidths=[4*cm]*4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#10141c")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.6*cm))

    story.append(Paragraph("Scan Details", styles["CSHeading"]))
    table_data = [["Scan Type", "Target", "Result", "Risk", "Date"]]
    for s in scans:
        table_data.append([s["scan_type"], str(s["target"])[:30], str(s["result"])[:30], s["risk_level"], str(s["date"])[:16]])

    detail_table = Table(table_data, colWidths=[3.2*cm, 3.5*cm, 4*cm, 2*cm, 3.3*cm], repeatRows=1)
    detail_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
    ]))
    story.append(detail_table)

    doc.build(story)
    return output_path
