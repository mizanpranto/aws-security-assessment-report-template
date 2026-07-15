"""
AWS Security Assessment Report Generator
=========================================
Author: Your Name — Cloud Security Consultant
Usage: python generate_report.py
Output: aws_security_assessment_report.pdf
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.pdfgen import canvas
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
from datetime import date
import os

# ─────────────────────────────────────────────
# BRAND COLORS
# ─────────────────────────────────────────────
DARK       = colors.HexColor("#0D1117")
DARK2      = colors.HexColor("#161B22")
GREEN      = colors.HexColor("#1D9E75")
GREEN_LIGHT= colors.HexColor("#E1F5EE")
BLUE       = colors.HexColor("#185FA5")
BLUE_LIGHT = colors.HexColor("#E3EEF9")
RED        = colors.HexColor("#C0392B")
RED_LIGHT  = colors.HexColor("#FCEBEB")
ORANGE     = colors.HexColor("#E67E22")
ORANGE_LIGHT=colors.HexColor("#FAEEDA")
GRAY       = colors.HexColor("#6E7681")
GRAY_LIGHT = colors.HexColor("#F6F8FA")
WHITE      = colors.white
BLACK      = colors.HexColor("#0D1117")

# ─────────────────────────────────────────────
# INTERACTIVE INPUT WIZARD
# ─────────────────────────────────────────────

def separator(title=""):
    width = 60
    print("\n" + "─" * width)
    if title:
        print(f"  {title}")
        print("─" * width)

def prompt(label, default=None, required=True):
    """Ask a single question. Shows default in brackets if provided."""
    hint = f" [{default}]" if default else ""
    while True:
        val = input(f"  {label}{hint}: ").strip()
        if val:
            return val
        if default is not None:
            return default
        if not required:
            return ""
        print("  ⚠  This field is required. Please enter a value.")

def prompt_multiline(label):
    """Collect a paragraph — user types text, blank line to finish."""
    print(f"  {label}")
    print("  (Type your text. Press Enter twice when done.)")
    lines = []
    while True:
        line = input("  > ")
        if line == "" and lines:
            break
        lines.append(line)
    return " ".join(lines)

def prompt_list(label, example=""):
    """Collect multiple items, one per line. Blank line to finish."""
    print(f"\n  {label}")
    if example:
        print(f"  Example: {example}")
    print("  (Enter one item per line. Blank line when done.)")
    items = []
    while True:
        val = input(f"  {len(items)+1}. ").strip()
        if val == "":
            if items:
                break
            print("  ⚠  Add at least one item.")
        else:
            items.append(val)
    return items

def prompt_severity():
    """Show severity menu and return chosen value."""
    options = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW"}
    while True:
        print("  Severity:  1) CRITICAL   2) HIGH   3) MEDIUM   4) LOW")
        choice = input("  Choose [1-4]: ").strip()
        if choice in options:
            return options[choice]
        print("  ⚠  Please enter 1, 2, 3, or 4.")

def collect_findings():
    """Collect findings one by one until user says done."""
    findings = []
    separator("FINDINGS ENTRY")
    print("  You will enter findings one by one.")
    print("  Enter as many as you found. Type 'done' at any finding ID to finish.\n")

    idx = 1
    while True:
        finding_id = f"AWF-{idx:03d}"
        print(f"\n  ── Finding #{idx}  ({finding_id}) ──")
        title_check = input(f"  Title (or type 'done' to finish): ").strip()
        if title_check.lower() == "done":
            if not findings:
                print("  ⚠  You need at least one finding.")
                continue
            break

        sev      = prompt_severity()
        category = prompt("Category (e.g. IAM, S3, EC2, RDS, Logging, VPC, Encryption)")
        desc     = prompt_multiline("Description — what did you find?")
        impact   = prompt("Impact — what could happen if exploited?")
        rec      = prompt_multiline("Recommendation — how to fix it?")
        refs     = prompt("Reference (e.g. CIS Benchmark control)", default="AWS CIS Benchmark v1.5")

        findings.append({
            "id":             finding_id,
            "severity":       sev,
            "category":       category,
            "title":          title_check,
            "description":    desc,
            "impact":         impact,
            "recommendation": rec,
            "references":     refs,
        })
        print(f"\n  ✅ Finding {finding_id} saved.")
        idx += 1

    return findings

def calculate_risk_summary(findings):
    """Auto-calculate counts and score from findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] += 1

    total = len(findings)
    # Score: start at 100, deduct by severity weight
    deductions = counts["CRITICAL"]*20 + counts["HIGH"]*10 + counts["MEDIUM"]*5 + counts["LOW"]*2
    score = max(0, 100 - deductions)

    if score >= 80:
        rating = "GOOD"
    elif score >= 60:
        rating = "FAIR"
    elif score >= 40:
        rating = "NEEDS IMPROVEMENT"
    else:
        rating = "CRITICAL RISK"

    return {
        "critical": counts["CRITICAL"],
        "high":     counts["HIGH"],
        "medium":   counts["MEDIUM"],
        "low":      counts["LOW"],
        "total":    total,
        "score":    score,
        "rating":   rating,
    }

def build_remediation_roadmap(findings):
    """Auto-group findings into roadmap phases by severity."""
    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        groups[f["severity"]].append(f"{f['id']}: {f['title']}")

    roadmap = []
    if groups["CRITICAL"]:
        roadmap.append(("Immediate (0–7 days)",   "CRITICAL", groups["CRITICAL"]))
    if groups["HIGH"]:
        roadmap.append(("Short-term (7–30 days)", "HIGH",     groups["HIGH"]))
    if groups["MEDIUM"]:
        roadmap.append(("Medium-term (30–90 days)","MEDIUM",  groups["MEDIUM"]))
    if groups["LOW"]:
        roadmap.append(("Low priority (90+ days)", "LOW",     groups["LOW"]))
    return roadmap

def collect_report_data():
    """Full interactive wizard — returns complete REPORT_DATA dict."""

    print("\n")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║     AWS SECURITY ASSESSMENT REPORT GENERATOR            ║")
    print("║     Cloud Security Consultant Tool                      ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # ── CONSULTANT INFO ──────────────────────────────────────────────────────
    separator("STEP 1 of 4 — YOUR CONSULTANT DETAILS")
    print("  (These appear in the report header and footer)\n")
    consultant_name  = prompt("Your full name",  default="Your Name")
    consultant_title = prompt("Your title",       default="Cloud Security Consultant")
    consultant_email = prompt("Your email",       default="hello@yoursite.com")
    consultant_certs = prompt("Your certifications", default="AWS SAA Certified | ISO 27001 | NIST | GDPR")

    # ── CLIENT INFO ──────────────────────────────────────────────────────────
    separator("STEP 2 of 4 — CLIENT DETAILS")
    print("  (Details of the company you assessed)\n")
    client_name     = prompt("Client company name",  default="Acme Startup Inc.")
    client_industry = prompt("Client industry",       default="SaaS")
    aws_account_id  = prompt("AWS Account ID (12 digits)", default="123456789012")
    report_version  = prompt("Report version",        default="1.0")
    assessment_date = prompt("Assessment date",       default=date.today().strftime("%B %d, %Y"))

    # ── SCOPE ────────────────────────────────────────────────────────────────
    separator("STEP 3 of 4 — ASSESSMENT SCOPE")
    scope = prompt_list(
        "What areas did you assess?",
        example="IAM Users & Roles"
    )

    # ── FINDINGS ─────────────────────────────────────────────────────────────
    separator("STEP 4 of 4 — FINDINGS")
    findings = collect_findings()

    # ── AUTO-GENERATE SUMMARY ─────────────────────────────────────────────────
    separator("AUTO-GENERATING EXECUTIVE SUMMARY & ROADMAP")
    risk_summary = calculate_risk_summary(findings)
    roadmap      = build_remediation_roadmap(findings)

    # Auto-build executive summary
    executive_summary = (
        f"This AWS Security Assessment was conducted on the {client_name} AWS environment "
        f"on {assessment_date}. The assessment identified {risk_summary['total']} findings across "
        f"{', '.join(set(f['category'] for f in findings))}. "
        f"Of these, {risk_summary['critical']} are Critical, {risk_summary['high']} are High, "
        f"{risk_summary['medium']} are Medium, and {risk_summary['low']} are Low severity. "
        f"The overall security posture score is {risk_summary['score']}/100 — rated {risk_summary['rating']}. "
        f"Immediate remediation of Critical and High findings is strongly advised."
    )

    print(f"\n  ✅ Executive summary generated automatically.")
    print(f"  ✅ Security score: {risk_summary['score']}/100 ({risk_summary['rating']})")
    print(f"  ✅ Remediation roadmap built from {risk_summary['total']} findings.")

    # ── OUTPUT FILENAME ───────────────────────────────────────────────────────
    separator("OUTPUT")
    safe_name   = client_name.lower().replace(" ", "_").replace(".", "")
    default_out = f"aws_security_report_{safe_name}.pdf"
    output_path = prompt(f"Output PDF filename", default=default_out)
    if not output_path.endswith(".pdf"):
        output_path += ".pdf"

    return {
        "client_name":        client_name,
        "client_industry":    client_industry,
        "aws_account_id":     aws_account_id,
        "assessment_date":    assessment_date,
        "report_version":     report_version,
        "consultant_name":    consultant_name,
        "consultant_title":   consultant_title,
        "consultant_email":   consultant_email,
        "consultant_certs":   consultant_certs,
        "scope":              scope,
        "executive_summary":  executive_summary,
        "risk_summary":       risk_summary,
        "findings":           findings,
        "remediation_roadmap":roadmap,
        "_output_path":       output_path,
    }


# ─────────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────────
def build_styles():
    base = getSampleStyleSheet()

    styles = {
        "cover_title": ParagraphStyle("cover_title",
            fontName="Helvetica-Bold", fontSize=28, textColor=WHITE,
            leading=34, spaceAfter=8),

        "cover_sub": ParagraphStyle("cover_sub",
            fontName="Helvetica", fontSize=13, textColor=colors.HexColor("#9FE1CB"),
            leading=18, spaceAfter=4),

        "cover_meta": ParagraphStyle("cover_meta",
            fontName="Helvetica", fontSize=10, textColor=colors.HexColor("#8B949E"),
            leading=14),

        "section_header": ParagraphStyle("section_header",
            fontName="Helvetica-Bold", fontSize=14, textColor=DARK,
            spaceBefore=18, spaceAfter=10,
            borderPad=6, leading=18),

        "sub_header": ParagraphStyle("sub_header",
            fontName="Helvetica-Bold", fontSize=11, textColor=DARK,
            spaceBefore=10, spaceAfter=4, leading=14),

        "body": ParagraphStyle("body",
            fontName="Helvetica", fontSize=9.5, textColor=colors.HexColor("#24292F"),
            leading=14, spaceAfter=4),

        "body_small": ParagraphStyle("body_small",
            fontName="Helvetica", fontSize=8.5, textColor=GRAY,
            leading=12, spaceAfter=2),

        "finding_title": ParagraphStyle("finding_title",
            fontName="Helvetica-Bold", fontSize=10, textColor=DARK,
            leading=13, spaceAfter=3),

        "finding_body": ParagraphStyle("finding_body",
            fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#24292F"),
            leading=13, spaceAfter=2),

        "label": ParagraphStyle("label",
            fontName="Helvetica-Bold", fontSize=8, textColor=GRAY,
            leading=11, spaceAfter=1),

        "toc_item": ParagraphStyle("toc_item",
            fontName="Helvetica", fontSize=10, textColor=BLUE,
            leading=16, leftIndent=10),

        "footer_text": ParagraphStyle("footer_text",
            fontName="Helvetica", fontSize=7.5, textColor=GRAY,
            leading=10, alignment=TA_CENTER),
    }
    return styles


# ─────────────────────────────────────────────
# SEVERITY HELPERS
# ─────────────────────────────────────────────
SEV_COLORS = {
    "CRITICAL": (RED,        RED_LIGHT,   colors.HexColor("#C0392B")),
    "HIGH":     (ORANGE,     ORANGE_LIGHT,colors.HexColor("#E67E22")),
    "MEDIUM":   (BLUE,       BLUE_LIGHT,  colors.HexColor("#185FA5")),
    "LOW":      (GREEN,      GREEN_LIGHT, colors.HexColor("#1D9E75")),
}

def sev_badge(sev):
    fg, bg, border = SEV_COLORS.get(sev, (GRAY, GRAY_LIGHT, GRAY))
    return Table(
        [[Paragraph(f'<font color="{fg.hexval()}" size="7"><b>{sev}</b></font>',
                    ParagraphStyle("b", fontName="Helvetica-Bold", fontSize=7,
                                   textColor=fg, alignment=TA_CENTER))]],
        colWidths=[55],
        style=TableStyle([
            ("BACKGROUND",  (0,0), (-1,-1), bg),
            ("BOX",         (0,0), (-1,-1), 0.5, border),
            ("ROUNDEDCORNERS", [3]),
            ("TOPPADDING",  (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING",(0,0), (-1,-1), 6),
        ])
    )


# ─────────────────────────────────────────────
# PAGE TEMPLATE — header & footer on every page
# ─────────────────────────────────────────────
class ReportCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        self.data   = kwargs.pop("data", {})
        self._pages = []
        super().__init__(*args, **kwargs)

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for page_num, page in enumerate(self._pages, 1):
            self.__dict__.update(page)
            self._draw_header_footer(page_num, total)
            super().showPage()
        super().save()

    def _draw_header_footer(self, page_num, total):
        W, H = A4
        d    = self.data

        if page_num == 1:
            return  # Cover page — no header/footer

        # Header bar
        self.setFillColor(DARK)
        self.rect(0, H - 22*mm, W, 22*mm, fill=1, stroke=0)
        self.setFillColor(GREEN)
        self.rect(0, H - 22*mm, 4, 22*mm, fill=1, stroke=0)

        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(WHITE)
        self.drawString(14*mm, H - 13*mm, "AWS SECURITY ASSESSMENT REPORT")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#8B949E"))
        self.drawRightString(W - 14*mm, H - 13*mm, f"{d['client_name']}  ·  CONFIDENTIAL")

        # Footer
        self.setFillColor(GRAY_LIGHT)
        self.rect(0, 0, W, 12*mm, fill=1, stroke=0)
        self.setFillColor(GREEN)
        self.rect(0, 0, W, 1, fill=1, stroke=0)

        self.setFont("Helvetica", 7)
        self.setFillColor(GRAY)
        self.drawString(14*mm, 4*mm,
            f"Prepared by {d['consultant_name']}  ·  {d['consultant_email']}  ·  {d['consultant_certs']}")
        self.drawRightString(W - 14*mm, 4*mm, f"Page {page_num} of {total}")


# ─────────────────────────────────────────────
# BUILD REPORT
# ─────────────────────────────────────────────
def build_report(output_path="aws_security_assessment_report.pdf"):
    d  = REPORT_DATA
    st = build_styles()
    W, H = A4

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=14*mm, rightMargin=14*mm,
        topMargin=28*mm, bottomMargin=18*mm,
        title="AWS Security Assessment Report",
        author=d["consultant_name"],
    )

    story = []

    # ── COVER PAGE ──────────────────────────────────────────────────────────
    # Dark background via a big table
    cover_bg = Table(
        [[
            Table([
                [Paragraph("☁️ AWS SECURITY", st["cover_title"])],
                [Paragraph("ASSESSMENT REPORT", st["cover_title"])],
                [Spacer(1, 6)],
                [Paragraph(f"Prepared for: {d['client_name']}", st["cover_sub"])],
                [Paragraph(f"Industry: {d['client_industry']}", st["cover_meta"])],
                [Paragraph(f"AWS Account: {d['aws_account_id']}", st["cover_meta"])],
                [Paragraph(f"Date: {d['assessment_date']}", st["cover_meta"])],
                [Paragraph(f"Version: {d['report_version']}", st["cover_meta"])],
                [Spacer(1, 20)],
                [HRFlowable(width="100%", thickness=1, color=colors.HexColor("#30363D"))],
                [Spacer(1, 10)],
                [Paragraph(f"Consultant: {d['consultant_name']}", st["cover_sub"])],
                [Paragraph(f"{d['consultant_title']}", st["cover_meta"])],
                [Paragraph(f"{d['consultant_email']}", st["cover_meta"])],
                [Paragraph(f"{d['consultant_certs']}", st["cover_meta"])],
                [Spacer(1, 30)],
                [Paragraph("⚠  CONFIDENTIAL — For authorized recipients only", ParagraphStyle(
                    "conf", fontName="Helvetica-Bold", fontSize=9,
                    textColor=ORANGE, leading=12)
                )],
            ], colWidths=[W - 28*mm],
               style=TableStyle([
                   ("BACKGROUND",   (0,0),(-1,-1), DARK),
                   ("LEFTPADDING",  (0,0),(-1,-1), 20),
                   ("RIGHTPADDING", (0,0),(-1,-1), 20),
                   ("TOPPADDING",   (0,0),(-1,-1), 4),
                   ("BOTTOMPADDING",(0,0),(-1,-1), 4),
               ]))
        ]],
        colWidths=[W - 28*mm],
        style=TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), DARK),
            ("TOPPADDING",    (0,0),(-1,-1), 50),
            ("BOTTOMPADDING", (0,0),(-1,-1), 50),
            ("LEFTPADDING",   (0,0),(-1,-1), 0),
            ("RIGHTPADDING",  (0,0),(-1,-1), 0),
        ])
    )
    story.append(cover_bg)
    story.append(PageBreak())

    # ── TABLE OF CONTENTS ────────────────────────────────────────────────────
    story.append(Paragraph("Table of Contents", st["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))
    toc_items = [
        "1.  Executive Summary",
        "2.  Assessment Scope",
        "3.  Risk Summary & Security Score",
        "4.  Detailed Findings",
        "5.  Remediation Roadmap",
        "6.  Appendix — AWS Services Reference",
    ]
    for item in toc_items:
        story.append(Paragraph(item, st["toc_item"]))
    story.append(PageBreak())

    # ── 1. EXECUTIVE SUMMARY ─────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", st["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))
    story.append(Paragraph(d["executive_summary"], st["body"]))
    story.append(Spacer(1, 12))

    # Risk score box — usable width = A4 - margins = 210mm - 28mm = 182mm
    rs = d["risk_summary"]
    score_color = RED if rs["score"] < 50 else (ORANGE if rs["score"] < 70 else GREEN)

    LEFT_W  = 70*mm   # score panel
    RIGHT_W = 112*mm  # breakdown panel
    TOTAL_W = LEFT_W + RIGHT_W  # 182mm = full content width

    # Left panel: score number stacked vertically
    left_panel = Table([
        [Paragraph(f'<font size="42" color="{score_color.hexval()}"><b>{rs["score"]}</b></font>',
                   ParagraphStyle("sc", alignment=TA_CENTER, leading=48, fontName="Helvetica-Bold"))],
        [Paragraph('<font size="9" color="#6E7681">out of 100</font>',
                   ParagraphStyle("sc2", alignment=TA_CENTER, leading=12))],
        [Spacer(1, 4)],
        [Paragraph('<font size="9" color="#6E7681"><b>SECURITY SCORE</b></font>',
                   ParagraphStyle("sc3", alignment=TA_CENTER, leading=12, fontName="Helvetica-Bold"))],
        [Paragraph(f'<font size="9" color="{score_color.hexval()}"><b>{rs["rating"]}</b></font>',
                   ParagraphStyle("sc4", alignment=TA_CENTER, leading=13, fontName="Helvetica-Bold"))],
    ], colWidths=[LEFT_W],
       style=TableStyle([
           ("BACKGROUND",    (0,0), (-1,-1), GRAY_LIGHT),
           ("ALIGN",         (0,0), (-1,-1), "CENTER"),
           ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
           ("TOPPADDING",    (0,0), (-1,-1), 3),
           ("BOTTOMPADDING", (0,0), (-1,-1), 3),
           ("TOPPADDING",    (0,0), (0,0),   18),
           ("BOTTOMPADDING", (0,4), (-1,-1), 18),
       ]))

    # Right panel: breakdown table with fixed column widths
    LABEL_W = 70*mm
    VALUE_W = RIGHT_W - 16*mm - LABEL_W  # account for left padding
    breakdown = Table([
        [Paragraph('<b>Critical</b>', ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=RED)),
         Paragraph(f'<b>{rs["critical"]}</b>', ParagraphStyle("sv", fontSize=13, fontName="Helvetica-Bold", textColor=RED, alignment=TA_RIGHT))],
        [Paragraph('<b>High</b>',     ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=ORANGE)),
         Paragraph(f'<b>{rs["high"]}</b>',     ParagraphStyle("sv", fontSize=13, fontName="Helvetica-Bold", textColor=ORANGE, alignment=TA_RIGHT))],
        [Paragraph('<b>Medium</b>',   ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=BLUE)),
         Paragraph(f'<b>{rs["medium"]}</b>',   ParagraphStyle("sv", fontSize=13, fontName="Helvetica-Bold", textColor=BLUE, alignment=TA_RIGHT))],
        [Paragraph('<b>Low</b>',      ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=GREEN)),
         Paragraph(f'<b>{rs["low"]}</b>',      ParagraphStyle("sv", fontSize=13, fontName="Helvetica-Bold", textColor=GREEN, alignment=TA_RIGHT))],
        [Paragraph('<b>Total</b>',    ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=DARK)),
         Paragraph(f'<b>{rs["total"]}</b>',    ParagraphStyle("sv", fontSize=13, fontName="Helvetica-Bold", textColor=DARK, alignment=TA_RIGHT))],
    ], colWidths=[LABEL_W, RIGHT_W - 16*mm - LABEL_W],
       style=TableStyle([
           ("LINEBELOW",     (0,0), (-1,-2), 0.5, colors.HexColor("#E6EDF3")),
           ("TOPPADDING",    (0,0), (-1,-1), 5),
           ("BOTTOMPADDING", (0,0), (-1,-1), 5),
           ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
       ]))

    right_panel = Table([
        [Paragraph('<b>Finding Breakdown</b>',
                   ParagraphStyle("fb", fontSize=10, fontName="Helvetica-Bold", textColor=DARK, leading=14, spaceAfter=6))],
        [breakdown],
    ], colWidths=[RIGHT_W],
       style=TableStyle([
           ("BACKGROUND",    (0,0), (-1,-1), WHITE),
           ("LEFTPADDING",   (0,0), (-1,-1), 16),
           ("RIGHTPADDING",  (0,0), (-1,-1), 16),
           ("TOPPADDING",    (0,0), (-1,-1), 14),
           ("BOTTOMPADDING", (0,0), (-1,-1), 14),
           ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#E6EDF3")),
       ]))

    score_table = Table(
        [[left_panel, right_panel]],
        colWidths=[LEFT_W, RIGHT_W],
        style=TableStyle([
            ("BOX",    (0,0), (-1,-1), 1,   colors.HexColor("#E6EDF3")),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING",  (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 0),
            ("TOPPADDING",   (0,0), (-1,-1), 0),
            ("BOTTOMPADDING",(0,0), (-1,-1), 0),
        ])
    )

    story.append(score_table)
    story.append(Spacer(1, 16))

    # ── 2. ASSESSMENT SCOPE ──────────────────────────────────────────────────
    story.append(Paragraph("2. Assessment Scope", st["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))
    scope_rows = [[Paragraph(f"✓  {item}", st["body"])] for item in d["scope"]]
    scope_table = Table(scope_rows, colWidths=[W - 28*mm],
        style=TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), GRAY_LIGHT),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 14),
            ("LINEBELOW",     (0,0), (-1,-2), 0.5, colors.HexColor("#E6EDF3")),
        ]))
    story.append(scope_table)
    story.append(PageBreak())

    # ── 3. RISK SUMMARY ──────────────────────────────────────────────────────
    story.append(Paragraph("3. Risk Summary & Security Score", st["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))

    # Category breakdown table
    cat_counts = {}
    for f in d["findings"]:
        cat_counts[f["category"]] = cat_counts.get(f["category"], 0) + 1

    cat_rows = [[
        Paragraph("<b>Category</b>", ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
        Paragraph("<b>Findings</b>", ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)),
        Paragraph("<b>Severity Distribution</b>", ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
    ]]
    for cat, cnt in cat_counts.items():
        sev_dist = {}
        for f in d["findings"]:
            if f["category"] == cat:
                sev_dist[f["severity"]] = sev_dist.get(f["severity"], 0) + 1
        dist_str = "  ".join([f'{s}: {c}' for s, c in sev_dist.items()])
        cat_rows.append([
            Paragraph(cat, st["body"]),
            Paragraph(str(cnt), ParagraphStyle("c", fontSize=9, fontName="Helvetica-Bold", textColor=DARK, alignment=TA_CENTER)),
            Paragraph(dist_str, st["body_small"]),
        ])

    cat_table = Table(cat_rows, colWidths=[50*mm, 25*mm, 80*mm],
        style=TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  DARK),
            ("BACKGROUND",    (0,1), (-1,-1), GRAY_LIGHT),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, GRAY_LIGHT]),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#E6EDF3")),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ]))
    story.append(cat_table)
    story.append(PageBreak())

    # ── 4. DETAILED FINDINGS ─────────────────────────────────────────────────
    story.append(Paragraph("4. Detailed Findings", st["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=14))

    for idx, finding in enumerate(d["findings"]):
        sev   = finding["severity"]
        fg, bg, border = SEV_COLORS.get(sev, (GRAY, GRAY_LIGHT, GRAY))

        # Finding card
        header_row = Table([[
            Paragraph(f'<font color="{fg.hexval()}"><b>[{finding["id"]}]</b></font>  '
                      f'<b>{finding["title"]}</b>',
                      ParagraphStyle("ft", fontName="Helvetica-Bold", fontSize=10,
                                     textColor=DARK, leading=13)),
            sev_badge(sev),
        ]], colWidths=[W - 28*mm - 65, 60],
           style=TableStyle([
               ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
               ("ALIGN",  (1,0),(-1,-1), "RIGHT"),
           ]))

        body_data = [
            [Paragraph("Category", st["label"]),      Paragraph(finding["category"], st["finding_body"])],
            [Paragraph("Description", st["label"]),   Paragraph(finding["description"], st["finding_body"])],
            [Paragraph("Impact", st["label"]),         Paragraph(finding["impact"], st["finding_body"])],
            [Paragraph("Recommendation", st["label"]),Paragraph(finding["recommendation"], st["finding_body"])],
            [Paragraph("Reference", st["label"]),      Paragraph(finding["references"], st["body_small"])],
        ]
        body_table = Table(body_data, colWidths=[28*mm, W - 28*mm - 34*mm],
            style=TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), bg),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING",   (0,0), (0,-1),  10),
                ("LEFTPADDING",   (1,0), (1,-1),  6),
                ("RIGHTPADDING",  (0,0), (-1,-1), 8),
                ("LINEBELOW",     (0,0), (-1,-2), 0.5, colors.HexColor("#E6EDF3")),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ]))

        card = Table([
            [header_row],
            [body_table],
        ], colWidths=[W - 28*mm],
           style=TableStyle([
               ("BOX",          (0,0),(-1,-1), 1, border),
               ("BACKGROUND",   (0,0),(-1,0),  colors.HexColor("#F6F8FA")),
               ("TOPPADDING",   (0,0),(-1,0),  8),
               ("BOTTOMPADDING",(0,0),(-1,0),  8),
               ("LEFTPADDING",  (0,0),(-1,-1), 10),
               ("RIGHTPADDING", (0,0),(-1,-1), 10),
               ("TOPPADDING",   (0,1),(-1,-1), 0),
               ("BOTTOMPADDING",(0,1),(-1,-1), 0),
               ("LEFTPADDING",  (0,1),(-1,-1), 0),
               ("RIGHTPADDING", (0,1),(-1,-1), 0),
           ]))

        story.append(KeepTogether([card, Spacer(1, 10)]))

    story.append(PageBreak())

    # ── 5. REMEDIATION ROADMAP ───────────────────────────────────────────────
    story.append(Paragraph("5. Remediation Roadmap", st["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))

    for phase, sev_label, items in d["remediation_roadmap"]:
        fg, bg, border = SEV_COLORS.get(sev_label, (GRAY, GRAY_LIGHT, GRAY))
        phase_header = Table([[
            Paragraph(f'<b>{phase}</b>',
                      ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=10,
                                     textColor=fg, leading=13)),
            sev_badge(sev_label),
        ]], colWidths=[W - 28*mm - 65, 60],
           style=TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(1,0),(-1,-1),"RIGHT")]))

        item_rows = [[Paragraph(f"→  {item}", st["body"])] for item in items]
        items_table = Table(item_rows, colWidths=[W - 28*mm],
            style=TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), bg),
                ("LEFTPADDING",   (0,0),(-1,-1), 16),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                ("LINEBELOW",     (0,0),(-1,-2), 0.5, colors.HexColor("#E6EDF3")),
            ]))

        phase_card = Table([
            [phase_header],
            [items_table],
        ], colWidths=[W - 28*mm],
           style=TableStyle([
               ("BOX",          (0,0),(-1,-1), 1, border),
               ("BACKGROUND",   (0,0),(-1,0),  colors.HexColor("#F6F8FA")),
               ("TOPPADDING",   (0,0),(-1,0),  8),
               ("BOTTOMPADDING",(0,0),(-1,0),  8),
               ("LEFTPADDING",  (0,0),(-1,0),  10),
               ("RIGHTPADDING", (0,0),(-1,0),  10),
               ("TOPPADDING",   (0,1),(-1,-1), 0),
               ("BOTTOMPADDING",(0,1),(-1,-1), 0),
               ("LEFTPADDING",  (0,1),(-1,-1), 0),
               ("RIGHTPADDING", (0,1),(-1,-1), 0),
           ]))
        story.append(phase_card)
        story.append(Spacer(1, 10))

    story.append(PageBreak())

    # ── 6. APPENDIX ──────────────────────────────────────────────────────────
    story.append(Paragraph("6. Appendix — AWS Services Reference", st["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))

    appendix_data = [
        [Paragraph("<b>AWS Service</b>",   ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
         Paragraph("<b>Purpose in Security</b>", ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE))],
        ["IAM",            "Identity & Access Management — users, roles, policies"],
        ["CloudTrail",     "API activity logging across all AWS services and regions"],
        ["GuardDuty",      "Intelligent threat detection using ML and anomaly detection"],
        ["Security Hub",   "Centralised security findings aggregation and compliance checks"],
        ["AWS Config",     "Configuration history and compliance rules for AWS resources"],
        ["VPC / SG / NACL","Network isolation, security groups, and network ACLs"],
        ["KMS",            "Key Management Service — encryption key creation and rotation"],
        ["S3 Block Public Access", "Account-level protection against public S3 exposure"],
        ["AWS Inspector",  "Automated vulnerability scanning for EC2 and containers"],
        ["Macie",          "ML-powered sensitive data discovery in S3 (PII, credentials)"],
    ]

    app_rows = []
    for i, row in enumerate(appendix_data):
        if i == 0:
            app_rows.append(row)
        else:
            app_rows.append([
                Paragraph(row[0], ParagraphStyle("ar", fontSize=9, fontName="Helvetica-Bold", textColor=DARK, leading=12)),
                Paragraph(row[1], st["body"]),
            ])

    app_table = Table(app_rows, colWidths=[50*mm, W - 28*mm - 55*mm],
        style=TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  DARK),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, GRAY_LIGHT]),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#E6EDF3")),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ]))
    story.append(app_table)
    story.append(Spacer(1, 20))

    # Closing statement
    story.append(Paragraph(
        f"This report was prepared by {d['consultant_name']} ({d['consultant_title']}) "
        f"on {d['assessment_date']}. All findings are based on the state of the AWS environment "
        f"at the time of assessment. Remediation should be verified through re-assessment. "
        f"For questions, contact {d['consultant_email']}.",
        ParagraphStyle("closing", fontName="Helvetica", fontSize=8.5,
                       textColor=GRAY, leading=13, alignment=TA_CENTER)
    ))

    # ── BUILD ─────────────────────────────────────────────────────────────────
    def make_canvas(*args, **kwargs):
        kwargs["data"] = d
        return ReportCanvas(*args, **kwargs)

    doc.build(story, canvasmaker=make_canvas)
    print(f"✅ Report generated: {output_path}")
    return output_path


if __name__ == "__main__":
    try:
        data        = collect_report_data()
        output_path = data.pop("_output_path")
        global REPORT_DATA
        REPORT_DATA = data
        print(f"\n  Generating PDF report...")
        build_report(output_path)
        print(f"\n  REPORT READY: {output_path}")
        print("  Deliver this PDF to your client!\n")
    except KeyboardInterrupt:
        print("\n\n  Cancelled. No report generated.\n")
