import io
from django.http import FileResponse, Http404
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from apps.scans.models import Scan
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

class DownloadPDFReportView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id, *args, **kwargs):
        try:
            scan = Scan.objects.prefetch_related('vulnerabilities__ai_remediation').get(id=scan_id, user=request.user)
        except Scan.DoesNotExist:
            raise Http404("Scan not found")
            
        # Create a file-like buffer to receive PDF data.
        buffer = io.BytesIO()
        
        # Create the PDF object, using the buffer as its "file."
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=54,
            leftMargin=54,
            topMargin=54,
            bottomMargin=54
        )
        
        # Container for the 'Flowables' (contents)
        story = []
        
        # Styling
        styles = getSampleStyleSheet()
        
        # Color definitions
        indigo_dark = colors.HexColor('#1e1b4b')
        indigo_main = colors.HexColor('#4f46e5')
        indigo_light = colors.HexColor('#e0e7ff')
        text_dark = colors.HexColor('#1f2937')
        border_gray = colors.HexColor('#e5e7eb')
        
        color_map = {
            'critical': colors.HexColor('#dc2626'),
            'high': colors.HexColor('#ea580c'),
            'medium': colors.HexColor('#eab308'),
            'low': colors.HexColor('#16a34a')
        }
        
        # Custom styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=28,
            textColor=indigo_dark,
            spaceAfter=6
        )
        
        subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#4b5563'),
            spaceAfter=20
        )
        
        h1_style = ParagraphStyle(
            'SectionH1',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            textColor=indigo_main,
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        )
        
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading3'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=indigo_dark,
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True
        )
        
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=text_dark
        )
        
        body_bold = ParagraphStyle(
            'ReportBodyBold',
            parent=body_style,
            fontName='Helvetica-Bold'
        )
        
        code_style = ParagraphStyle(
            'CodeBlock',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#111827'),
            backColor=colors.HexColor('#f9fafb'),
            borderColor=border_gray,
            borderWidth=1,
            borderPadding=6,
            spaceAfter=8
        )
        
        # Header / Title Block
        story.append(Paragraph("VulnSight Security Audit Report", title_style))
        story.append(Paragraph(f"Generated on {timezone_str()} | Framework Version 2.0 (Celery-Async Engine)", subtitle_style))
        story.append(Spacer(1, 10))
        
        # Meta table details
        meta_data = [
            [Paragraph("Target URL:", body_bold), Paragraph(scan.target_url, body_style)],
            [Paragraph("Scan Type:", body_bold), Paragraph(scan.scan_type.upper().replace('_', ' '), body_style)],
            [Paragraph("Status:", body_bold), Paragraph(scan.status.upper(), body_style)],
            [Paragraph("Started At:", body_bold), Paragraph(scan.started_at.strftime('%Y-%m-%d %H:%M:%S UTC'), body_style)],
            [Paragraph("Completed At:", body_bold), Paragraph(scan.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.completed_at else 'N/A', body_style)],
        ]
        
        meta_table = Table(meta_data, colWidths=[1.5*inch, 5.0*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f9fafb')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 1, border_gray),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", h1_style))
        vulns = scan.vulnerabilities.all()
        total_vulns = vulns.count()
        
        # Count severities
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for v in vulns:
            sev = v.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts['low'] += 1
                
        summary_text = (
            f"The automated security scanning sweep completed successfully. "
            f"A total of <b>{total_vulns}</b> vulnerabilities were identified during the audit."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 10))
        
        # Severity Table
        summary_data = [
            [
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Count</b>", body_style),
                Paragraph("<b>Threat Level Description</b>", body_style)
            ],
            [
                Paragraph("<font color='#dc2626'><b>Critical</b></font>", body_style),
                Paragraph(str(severity_counts['critical']), body_style),
                Paragraph("Severe risks allowing remote control or arbitrary data extraction.", body_style)
            ],
            [
                Paragraph("<font color='#ea580c'><b>High</b></font>", body_style),
                Paragraph(str(severity_counts['high']), body_style),
                Paragraph("Serious issues exposing key user actions (e.g. Session hijacking, XSS).", body_style)
            ],
            [
                Paragraph("<font color='#eab308'><b>Medium</b></font>", body_style),
                Paragraph(str(severity_counts['medium']), body_style),
                Paragraph("Information leaks, standard open backend ports or SSL configurations.", body_style)
            ],
            [
                Paragraph("<font color='#16a34a'><b>Low</b></font>", body_style),
                Paragraph(str(severity_counts['low']), body_style),
                Paragraph("Common open HTTP ports or minor system information disclosures.", body_style)
            ]
        ]
        
        summary_table = Table(summary_data, colWidths=[1.5*inch, 1.0*inch, 4.0*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), indigo_light),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 1, border_gray),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Findings Detail
        story.append(Paragraph("Vulnerability Findings Details", h1_style))
        
        if total_vulns == 0:
            story.append(Paragraph("No vulnerabilities were identified during this security sweep.", body_style))
        else:
            for idx, vuln in enumerate(vulns, 1):
                sev_color = color_map.get(vuln.severity.lower(), colors.HexColor('#6b7280'))
                
                # Title block of vulnerability
                vuln_title = Paragraph(f"<b>{idx}. {vuln.vulnerability_type}</b>", h2_style)
                story.append(vuln_title)
                
                # Metadata block
                vuln_meta = [
                    [Paragraph("Severity:", body_bold), Paragraph(f"<font color='{sev_color.hexval()}'><b>{vuln.severity.upper()}</b></font>", body_style)],
                    [Paragraph("Affected URL:", body_bold), Paragraph(vuln.affected_url, body_style)],
                ]
                vuln_meta_table = Table(vuln_meta, colWidths=[1.5*inch, 5.0*inch])
                vuln_meta_table.setStyle(TableStyle([
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('LINEBELOW', (0,0), (-1,-1), 0.5, border_gray),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ]))
                story.append(vuln_meta_table)
                story.append(Spacer(1, 6))
                
                # Description
                story.append(Paragraph("<b>Description:</b>", body_bold))
                story.append(Paragraph(vuln.description, body_style))
                story.append(Spacer(1, 6))
                
                # Evidence
                if vuln.evidence:
                    import json
                    try:
                        evidence_str = json.dumps(vuln.evidence, indent=2)
                    except Exception:
                        evidence_str = str(vuln.evidence)
                    story.append(Paragraph("<b>Evidence / Payload details:</b>", body_bold))
                    story.append(Paragraph(evidence_str.replace('\n', '<br/>').replace(' ', '&nbsp;'), code_style))
                    story.append(Spacer(1, 6))
                    
                # Static Remediation
                if vuln.remediation:
                    story.append(Paragraph("<b>Default Remediation:</b>", body_bold))
                    story.append(Paragraph(vuln.remediation, body_style))
                    story.append(Spacer(1, 6))
                
                # AI Recommendations Block
                if hasattr(vuln, 'ai_remediation'):
                    ai = vuln.ai_remediation
                    ai_title = Paragraph("<b>AI Remediation Insights (Gemini-Powered)</b>", ParagraphStyle(
                        'AITitle',
                        parent=body_bold,
                        textColor=indigo_main
                    ))
                    story.append(ai_title)
                    
                    ai_content = [
                        [Paragraph("<b>Explanation:</b>", body_bold), Paragraph(ai.explanation, body_style)],
                        [Paragraph("<b>Threat Impact:</b>", body_bold), Paragraph(ai.impact, body_style)],
                        [Paragraph("<b>Fix Steps:</b>", body_bold), Paragraph(ai.fix_recommendation, body_style)],
                        [Paragraph("<b>Secure Pattern:</b>", body_bold), Paragraph(f"<code>{ai.secure_coding}</code>", body_style)],
                    ]
                    ai_table = Table(ai_content, colWidths=[1.5*inch, 5.0*inch])
                    ai_table.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f5f3ff')), # Very light purple background
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ddd6fe')),
                        ('TOPPADDING', (0,0), (-1,-1), 5),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                        ('LEFTPADDING', (0,0), (-1,-1), 8),
                        ('RIGHTPADDING', (0,0), (-1,-1), 8),
                    ]))
                    story.append(ai_table)
                
                story.append(Spacer(1, 15))
                
        # Build PDF
        doc.build(story)
        
        # FileResponse sets the Content-Disposition header so the browser knows to download it.
        buffer.seek(0)
        filename = f"VulnSight_Report_Scan_{scan.id}.pdf"
        return FileResponse(buffer, as_attachment=True, filename=filename)

def timezone_str():
    from django.utils import timezone
    return timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')
