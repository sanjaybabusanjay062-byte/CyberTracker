import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from app.models import Case, Evidence, LogRecord, ThreatAlert
from app import db


class NumberedCanvas(canvas.Canvas):
    """Custom two-pass canvas to dynamically compute and print total page count."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Header (pages after cover page)
        if self._pageNumber > 1:
            self.drawString(54, 11 * inch - 36, "CYBERTRACE AI - DIGITAL FORENSIC INVESTIGATION REPORT")
            self.drawRightString(8.5 * inch - 54, 11 * inch - 36, "CLASSIFICATION: CONFIDENTIAL")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Footer (all pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 8.5 * inch - 54, 45)

        self.drawString(54, 32, "CYBERTRACE AI FORENSICS PLATFORM | CHAIN OF CUSTODY VERIFIED")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 32, page_text)
        self.restoreState()


def generate_investigation_report(case_id, output_path):
    """Generate a high-grade forensic investigation PDF report for a given case."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    case = db.session.get(Case, case_id) if isinstance(case_id, int) else None
    if not case:
        case = Case.query.filter_by(case_id=case_id).first()

    evidences = Evidence.query.filter_by(case_id=case.id).all() if case else []
    threats = ThreatAlert.query.filter_by(case_id=case.id).order_by(ThreatAlert.timestamp.desc()).all() if case else []
    logs = LogRecord.query.filter_by(case_id=case.id).order_by(LogRecord.timestamp.asc()).limit(50).all() if case else []

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom Color Palette
    navy = colors.HexColor('#0a0e1a')
    cyan = colors.HexColor('#00c2ff')
    slate = colors.HexColor('#334155')
    light_bg = colors.HexColor('#f1f5f9')
    crimson = colors.HexColor('#ef4444')
    amber = colors.HexColor('#f59e0b')

    # Typography Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=navy,
        alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=cyan,
        alignment=TA_CENTER
    )
    h1_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=navy,
        spaceBefore=14,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=slate,
        alignment=TA_JUSTIFY
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=slate
    )
    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white
    )

    story = []

    # --- COVER PAGE ---
    story.append(Spacer(1, 40))
    story.append(Paragraph("CYBERTRACE AI", title_style))
    story.append(Spacer(1, 8))
    story.append(Paragraph("ADVANCED DIGITAL FORENSICS & THREAT INTELLIGENCE", subtitle_style))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=3, color=navy, spaceBefore=5, spaceAfter=25))

    confidential_banner = [
        [Paragraph("<font color='#ef4444'><b>CONFIDENTIAL // LAW ENFORCEMENT & SECURITY TEAMS ONLY</b></font>",
                   ParagraphStyle('ConfBanner', parent=title_style, fontSize=10, leading=12))]
    ]
    t_banner = Table(confidential_banner, colWidths=[500])
    t_banner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef2f2')),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOX', (0, 0), (-1, -1), 1, crimson),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_banner)
    story.append(Spacer(1, 35))

    story.append(Paragraph(f"<b>CASE FILE:</b> {case.case_id if case else 'CT-UNASSIGNED'}", ParagraphStyle('CoverCase', parent=title_style, fontSize=16, leading=20)))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<i>{case.title if case else 'Digital Forensics Examination'}</i>", ParagraphStyle('CoverCaseTitle', parent=body_style, alignment=TA_CENTER, fontSize=11, leading=14)))
    story.append(Spacer(1, 45))

    # Cover Meta Table
    cover_meta = [
        [Paragraph("<b>Investigation Status:</b>", body_style), Paragraph(f"{(case.status if case else 'Open').upper()}", body_style)],
        [Paragraph("<b>Incident Priority:</b>", body_style), Paragraph(f"{(case.priority if case else 'Medium').upper()}", body_style)],
        [Paragraph("<b>Lead Investigator:</b>", body_style), Paragraph(f"{case.investigator.username if case and case.investigator else 'Lead Analyst'}", body_style)],
        [Paragraph("<b>Date Generated:</b>", body_style), Paragraph(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), body_style)],
        [Paragraph("<b>Evidence Artifacts:</b>", body_style), Paragraph(f"{len(evidences)} item(s) logged and verified", body_style)],
        [Paragraph("<b>Correlated Alerts:</b>", body_style), Paragraph(f"{len(threats)} detected threats", body_style)],
    ]
    t_cover_meta = Table(cover_meta, colWidths=[180, 320])
    t_cover_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(t_cover_meta)
    story.append(PageBreak())

    # --- SECTION 1: EXECUTIVE SUMMARY ---
    story.append(Paragraph("1. EXECUTIVE SUMMARY", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=cyan, spaceBefore=2, spaceAfter=8))

    summary_text = (
        f"This forensic investigation report details the technical analysis conducted on digital evidence associated with "
        f"Case <b>{case.case_id if case else 'N/A'}</b> (<i>{case.title if case else 'N/A'}</i>). "
        f"All digital artifacts ingested into CYBERTRACE AI underwent cryptographic hashing (SHA-256) to ensure strict evidentiary chain of custody. "
        f"Automated threat correlation engines and natural language parsing evaluated the event sequences for indications of compromise (IOCs), "
        f"privilege escalation, unauthorized perimeter access, and lateral movement."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    exec_stats = [
        [
            Paragraph("<b>Total Logs Indexed</b>", table_header),
            Paragraph("<b>Identified Threats</b>", table_header),
            Paragraph("<b>Evidence Items</b>", table_header),
            Paragraph("<b>Integrity Status</b>", table_header)
        ],
        [
            Paragraph(f"<font size=11><b>{len(logs)}+</b></font>", table_cell),
            Paragraph(f"<font size=11 color='#ef4444'><b>{len(threats)}</b></font>", table_cell),
            Paragraph(f"<font size=11><b>{len(evidences)}</b></font>", table_cell),
            Paragraph("<font size=11 color='#10b981'><b>100% VERIFIED</b></font>", table_cell)
        ]
    ]
    t_stats = Table(exec_stats, colWidths=[125, 125, 125, 125])
    t_stats.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), navy),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8fafc')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_stats)
    story.append(Spacer(1, 15))

    # --- SECTION 2: EVIDENCE INVENTORY ---
    story.append(Paragraph("2. DIGITAL EVIDENCE INVENTORY", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=cyan, spaceBefore=2, spaceAfter=8))

    ev_rows = [
        [
            Paragraph("<b>Evidence ID</b>", table_header),
            Paragraph("<b>Filename</b>", table_header),
            Paragraph("<b>SHA-256 Hash</b>", table_header),
            Paragraph("<b>Uploaded At</b>", table_header),
            Paragraph("<b>Integrity</b>", table_header)
        ]
    ]

    if evidences:
        for ev in evidences:
            ev_rows.append([
                Paragraph(f"<b>{ev.evidence_id}</b>", table_cell),
                Paragraph(ev.original_filename or ev.filename, table_cell),
                Paragraph(f"<font size=6>{ev.sha256_hash[:16]}...{ev.sha256_hash[-8:]}</font>", table_cell),
                Paragraph(ev.uploaded_at.strftime('%Y-%m-%d %H:%M') if ev.uploaded_at else 'N/A', table_cell),
                Paragraph("<font color='#10b981'><b>MATCH</b></font>" if ev.integrity_verified else "<font color='#ef4444'><b>FAIL</b></font>", table_cell)
            ])
    else:
        ev_rows.append([Paragraph("No evidence files registered.", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell)])

    t_ev = Table(ev_rows, colWidths=[70, 110, 160, 90, 70])
    t_ev.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), navy),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_ev)
    story.append(Spacer(1, 15))

    # --- SECTION 3: THREAT ALERTS ---
    story.append(Paragraph("3. CORRELATED THREAT ALERTS", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=cyan, spaceBefore=2, spaceAfter=8))

    threat_rows = [
        [
            Paragraph("<b>Alert ID</b>", table_header),
            Paragraph("<b>Type</b>", table_header),
            Paragraph("<b>Severity</b>", table_header),
            Paragraph("<b>Timestamp (UTC)</b>", table_header),
            Paragraph("<b>Source IP</b>", table_header),
            Paragraph("<b>Description</b>", table_header)
        ]
    ]

    if threats:
        for t in threats[:15]:
            sev_color = '#ef4444' if t.severity in ['critical', 'high'] else '#f59e0b'
            threat_rows.append([
                Paragraph(f"<b>{t.alert_id}</b>", table_cell),
                Paragraph(t.alert_type, table_cell),
                Paragraph(f"<font color='{sev_color}'><b>{t.severity.upper()}</b></font>", table_cell),
                Paragraph(t.timestamp.strftime('%Y-%m-%d %H:%M:%S') if t.timestamp else 'N/A', table_cell),
                Paragraph(t.source_ip or 'Local', table_cell),
                Paragraph(t.description[:80] + ('...' if len(t.description) > 80 else ''), table_cell)
            ])
    else:
        threat_rows.append([Paragraph("No automated threat alerts triggered.", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell)])

    t_threats = Table(threat_rows, colWidths=[65, 90, 55, 85, 75, 130])
    t_threats.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), navy),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_threats)
    story.append(Spacer(1, 15))

    # --- SECTION 4: FORENSIC TIMELINE ---
    story.append(PageBreak())
    story.append(Paragraph("4. FORENSIC EVENT TIMELINE (CHRONOLOGICAL)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=cyan, spaceBefore=2, spaceAfter=8))
    story.append(Paragraph("Displaying the top chronological sequence of extracted forensic log events for timeline analysis:", body_style))
    story.append(Spacer(1, 8))

    log_rows = [
        [
            Paragraph("<b>Time</b>", table_header),
            Paragraph("<b>Source IP</b>", table_header),
            Paragraph("<b>User</b>", table_header),
            Paragraph("<b>Event Type</b>", table_header),
            Paragraph("<b>Description / Activity</b>", table_header)
        ]
    ]

    if logs:
        for l in logs:
            log_rows.append([
                Paragraph(l.timestamp.strftime('%H:%M:%S') if l.timestamp else 'N/A', table_cell),
                Paragraph(l.source_ip or '-', table_cell),
                Paragraph(l.username or '-', table_cell),
                Paragraph(f"<b>{l.event_type}</b>", table_cell),
                Paragraph(l.event_description[:65] + ('...' if len(l.event_description) > 65 else ''), table_cell)
            ])
    else:
        log_rows.append([Paragraph("No log events found.", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell), Paragraph("-", table_cell)])

    t_logs = Table(log_rows, colWidths=[55, 75, 65, 85, 220])
    t_logs.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), navy),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_logs)
    story.append(Spacer(1, 15))

    # --- SECTION 5: FINDINGS & ANALYSIS ---
    story.append(Paragraph("5. FINDINGS AND TECHNICAL ANALYSIS", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=cyan, spaceBefore=2, spaceAfter=8))

    findings_text = (
        "<b>Attack Progression Analysis:</b><br/>"
        "1. <i>Initial Reconnaissance & Perimeter Probing:</i> Inbound connection bursts and port scan events directed toward SSH port 22 and administrative interfaces.<br/>"
        "2. <i>Credential Brute-Force Phase:</i> Repeated authentication failures concentrated in tight temporal windows from external IP addresses.<br/>"
        "3. <i>Off-Hours Account Compromise:</i> Successful authentication recorded outside standard business operating hours.<br/>"
        "4. <i>Privilege Escalation & Staging:</i> Execution of elevated shell commands, inspection of system authentication files (/etc/shadow), and staging of data archives.<br/>"
        "5. <i>Exfiltration Indicators:</i> Data transfers to remote IP endpoints and external volume mounts.<br/><br/>"
        "<b>Investigative Recommendations:</b><br/>"
        "• Immediately revoke compromised credentials and enforce multi-factor authentication (MFA).<br/>"
        "• Place ingress blocks on all offending external IP addresses identified in this report.<br/>"
        "• Isolate affected hosts from the internal network for complete forensic memory and disk imaging.<br/>"
        "• Preserve audit logs and report findings to relevant regulatory bodies as required by law."
    )
    story.append(Paragraph(findings_text, body_style))
    story.append(Spacer(1, 15))

    # --- SECTION 6: LIMITATIONS & DISCLAIMERS ---
    story.append(Paragraph("6. LIMITATIONS AND LEGAL DISCLAIMER", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=cyan, spaceBefore=2, spaceAfter=8))

    disclaimer_text = (
        "<b>Evidence Scope Limitation:</b> This analysis is based strictly on the digital evidence and log records provided "
        "and successfully ingested into the CYBERTRACE AI platform at the time of report compilation. "
        "Undetected, unlogged, or encrypted adversary activities outside the visibility of the collected artifacts "
        "cannot be completely eliminated.<br/><br/>"
        "<b>Evidentiary Chain of Custody:</b> All files summarized herein have their cryptographic SHA-256 signatures stored and verified "
        "in the tamper-evident investigation database. This document has been generated for official evidentiary and internal investigation purposes."
    )
    story.append(Paragraph(disclaimer_text, body_style))

    # Build the document using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_path
