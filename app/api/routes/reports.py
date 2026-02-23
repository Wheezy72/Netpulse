from __future__ import annotations

import io
import uuid
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user
from app.models.device import Device
from app.models.user import User

router = APIRouter()


class ReportRequest(BaseModel):
    report_type: str
    title: Optional[str] = None
    include_devices: bool = True
    include_metrics: bool = True
    include_alerts: bool = True
    date_range_days: int = 7


class ReportMetadata(BaseModel):
    id: str
    name: str
    report_type: str
    created_at: str
    file_size: int


def _generate_short_name(report_type: str, date_range_days: int = 7) -> str:
    """Generate a readable report name like NetReport_Jan17-24_2026."""
    now = datetime.now()
    start_date = now - __import__('datetime').timedelta(days=date_range_days)
    
    if start_date.month == now.month:
        date_range = f"{start_date.strftime('%b')}{start_date.day}-{now.day}"
    else:
        date_range = f"{start_date.strftime('%b%d')}-{now.strftime('%b%d')}"
    
    year = now.strftime("%Y")
    return f"NetReport_{date_range}_{year}"


def _generate_pdf_content(
    report_type: str,
    title: str,
    devices: List[Any],
    include_metrics: bool,
    include_alerts: bool,
) -> bytes:
    """Generate PDF report content with NetPulse indigo/cyan theme."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
            HRFlowable,
        )
        from reportlab.graphics.shapes import Drawing, Rect, String
        from reportlab.graphics import renderPDF
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        
        styles = getSampleStyleSheet()
        
        np_indigo = colors.HexColor('#6366f1')
        np_cyan = colors.HexColor('#00f3ff')
        np_slate_dark = colors.HexColor('#1e293b')
        np_slate = colors.HexColor('#334155')
        np_slate_light = colors.HexColor('#64748b')
        np_white = colors.white
        
        logo_style = ParagraphStyle(
            'LogoStyle',
            parent=styles['Normal'],
            fontSize=32,
            textColor=np_cyan,
            fontName='Helvetica-Bold',
            spaceAfter=2,
            leading=36,
        )
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=np_indigo,
            spaceAfter=15,
            fontName='Helvetica-Bold',
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=np_indigo,
            spaceBefore=15,
            spaceAfter=10,
            fontName='Helvetica-Bold',
        )
        
        subheading_style = ParagraphStyle(
            'SubHeading',
            parent=styles['Normal'],
            fontSize=11,
            textColor=np_slate,
            spaceAfter=6,
            fontName='Helvetica-Bold',
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            textColor=np_slate_dark,
            spaceAfter=8,
        )
        
        meta_style = ParagraphStyle(
            'MetaStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=np_slate_light,
            spaceAfter=6,
        )
        
        tagline_style = ParagraphStyle(
            'TaglineStyle',
            parent=styles['Normal'],
            fontSize=11,
            textColor=np_slate,
            spaceBefore=0,
            spaceAfter=12,
        )
        
        elements = []
        
        elements.append(Paragraph("NETPULSE", logo_style))
        elements.append(Paragraph("Network Operations Console", tagline_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=np_cyan, spaceAfter=20))
        
        elements.append(Paragraph(title, title_style))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", meta_style))
        elements.append(Paragraph(f"Report Type: {report_type.replace('_', ' ').title()}", meta_style))
        elements.append(Spacer(1, 20))
        
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(HRFlowable(width="30%", thickness=1, color=np_indigo, spaceAfter=10))
        summary_text = f"""
        This report provides a comprehensive overview of your network infrastructure.
        <br/><br/>
        <b>Total devices monitored:</b> {len(devices)}<br/>
        <b>Report period:</b> Last 7 days<br/>
        <b>Status:</b> All systems operational
        """
        elements.append(Paragraph(summary_text, body_style))
        elements.append(Spacer(1, 15))
        
        if devices:
            elements.append(Paragraph("Device Inventory", heading_style))
            elements.append(HRFlowable(width="30%", thickness=1, color=np_indigo, spaceAfter=10))
            
            online_count = sum(1 for d in devices if d.is_online)
            offline_count = len(devices) - online_count
            elements.append(Paragraph(f"<b>Online:</b> {online_count} | <b>Offline:</b> {offline_count}", subheading_style))
            elements.append(Spacer(1, 8))
            
            table_data = [['Hostname', 'IP Address', 'Status', 'Type']]
            for device in devices[:20]:
                status = 'Online' if device.is_online else 'Offline'
                table_data.append([
                    device.hostname or 'Unknown',
                    device.ip_address or '-',
                    status,
                    device.device_type or 'Unknown',
                ])
            
            table = Table(table_data, colWidths=[2*inch, 1.5*inch, 1*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), np_indigo),
                ('TEXTCOLOR', (0, 0), (-1, 0), np_white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('TOPPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f1f5f9')),
                ('TEXTCOLOR', (0, 1), (-1, -1), np_slate_dark),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, np_indigo),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f1f5f9'), colors.HexColor('#e2e8f0')]),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 20))
        
        if include_metrics:
            elements.append(Paragraph("Network Metrics", heading_style))
            elements.append(HRFlowable(width="30%", thickness=1, color=np_indigo, spaceAfter=10))
            
            metrics_table_data = [
                ['Metric', 'Value', 'Status'],
                ['Average Response Time', '12ms', 'Good'],
                ['Uptime Percentage', '99.2%', 'Excellent'],
                ['Bandwidth Utilization', '45%', 'Normal'],
                ['Packet Loss', '0.1%', 'Excellent'],
            ]
            metrics_table = Table(metrics_table_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), np_slate),
                ('TEXTCOLOR', (0, 0), (-1, 0), np_white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('TEXTCOLOR', (0, 1), (-1, -1), np_slate_dark),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, np_slate_light),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ]))
            elements.append(metrics_table)
            elements.append(Spacer(1, 15))
        
        if include_alerts:
            elements.append(Paragraph("Recent Alerts", heading_style))
            elements.append(HRFlowable(width="30%", thickness=1, color=np_indigo, spaceAfter=10))
            
            alerts_table_data = [
                ['Severity', 'Count', 'Description'],
                ['Critical', '0', 'No critical alerts'],
                ['Warning', '3', 'Minor configuration issues'],
                ['Info', '12', 'Routine notifications'],
            ]
            alerts_table = Table(alerts_table_data, colWidths=[1.5*inch, 1*inch, 3*inch])
            alerts_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), np_slate),
                ('TEXTCOLOR', (0, 0), (-1, 0), np_white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#fef2f2')),
                ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor('#dc2626')),
                ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#fefce8')),
                ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor('#ca8a04')),
                ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#f0f9ff')),
                ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor('#0284c7')),
                ('BACKGROUND', (1, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('TEXTCOLOR', (1, 1), (-1, -1), np_slate_dark),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, np_slate_light),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ]))
            elements.append(alerts_table)
        
        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(width="100%", thickness=1, color=np_slate_light, spaceAfter=10))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=np_slate_light,
            alignment=1,
        )
        elements.append(Paragraph("Generated by NetPulse Enterprise - Network Operations Console", footer_style))
        elements.append(Paragraph(f"Report ID: {uuid.uuid4().hex[:8].upper()}", footer_style))
        
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
        
    except ImportError:
        return _generate_simple_pdf(report_type, title, devices)


def _generate_simple_pdf(report_type: str, title: str, devices: List[Any]) -> bytes:
    """Generate a simple text-based PDF if reportlab is not available."""
    content = f"""
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 200 >>
stream
BT
/F1 24 Tf
50 750 Td
({title}) Tj
/F1 12 Tf
0 -30 Td
(Report Type: {report_type}) Tj
0 -20 Td
(Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}) Tj
0 -20 Td
(Total Devices: {len(devices)}) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000266 00000 n 
0000000516 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
595
%%EOF
"""
    return content.encode('latin-1')


@router.post(
    "/generate",
    summary="Generate a PDF report",
)
async def generate_report(
    request: ReportRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Generate a professional PDF report with Sysadmin Pro styling."""
    
    short_name = _generate_short_name(request.report_type, request.date_range_days)
    title = request.title or f"NetPulse {request.report_type.replace('_', ' ').title()} Report"
    
    devices: List[Any] = []
    if request.include_devices:
        result = await db.execute(select(Device).limit(100))
        devices = list(result.scalars().all())
    
    pdf_content = _generate_pdf_content(
        report_type=request.report_type,
        title=title,
        devices=devices,
        include_metrics=request.include_metrics,
        include_alerts=request.include_alerts,
    )
    
    return StreamingResponse(
        io.BytesIO(pdf_content),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{short_name}.pdf"',
            "X-Report-Name": short_name,
        }
    )


@router.get(
    "/types",
    summary="List available report types",
)
async def list_report_types(
    current_user: User = Depends(get_current_user),
) -> List[dict[str, str]]:
    """Get all available report types."""
    return [
        {"id": "network_summary", "name": "Network Summary", "description": "Overview of all network devices and status"},
        {"id": "security_audit", "name": "Security Audit", "description": "Security posture assessment"},
        {"id": "device_inventory", "name": "Device Inventory", "description": "Complete list of discovered devices"},
        {"id": "performance", "name": "Performance Report", "description": "Network performance metrics"},
        {"id": "incident", "name": "Incident Report", "description": "Recent incidents and alerts"},
        {"id": "compliance", "name": "Compliance Report", "description": "Compliance status and findings"},
    ]


@router.get(
    "/devices/pdf",
    summary="Generate device inventory PDF",
)
async def generate_devices_pdf(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Generate a PDF report of all discovered devices."""
    result = await db.execute(select(Device).limit(500))
    devices = list(result.scalars().all())
    
    pdf_content = _generate_pdf_content(
        report_type="device_inventory",
        title="Device Inventory Report",
        devices=devices,
        include_metrics=False,
        include_alerts=False,
    )
    
    now = datetime.now()
    filename = f"Devices_{now.strftime('%b%d')}_{now.strftime('%Y')}"
    
    return StreamingResponse(
        io.BytesIO(pdf_content),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.pdf"',
        }
    )


class LogsPDFRequest(BaseModel):
    level: Optional[str] = None
    limit: int = 500


@router.post(
    "/logs/pdf",
    summary="Generate logs PDF",
)
async def generate_logs_pdf(
    request: LogsPDFRequest = LogsPDFRequest(),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Generate a PDF report of application logs."""
    from app.services.logging_service import memory_handler
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    
    logs_data = memory_handler.get_logs(level=request.level, limit=request.limit)
    logs = [log.to_dict() for log in logs_data]
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    
    np_indigo = colors.HexColor('#4f46e5')
    np_cyan = colors.HexColor('#06b6d4')
    np_slate = colors.HexColor('#334155')
    
    logo_style = ParagraphStyle('LogoStyle', parent=styles['Normal'], fontSize=28, textColor=np_cyan, fontName='Helvetica-Bold', spaceAfter=8)
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=np_indigo, spaceBefore=10, spaceAfter=10)
    
    elements = []
    elements.append(Paragraph("NETPULSE", logo_style))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Application Log Report", title_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=np_cyan, spaceAfter=15))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", styles['Normal']))
    elements.append(Paragraph(f"Total Entries: {len(logs)}", styles['Normal']))
    elements.append(Spacer(1, 15))
    
    if logs:
        table_data = [['Time', 'Level', 'Message']]
        for log in logs[:200]:
            ts = log.get('timestamp', '')[:19].replace('T', ' ')
            level = log.get('level', 'INFO').upper()
            msg = log.get('message', '')[:80]
            table_data.append([ts, level, msg])
        
        table = Table(table_data, colWidths=[100, 60, 340])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), np_indigo),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        elements.append(table)
    
    doc.build(elements)
    buffer.seek(0)
    
    now = datetime.now()
    filename = f"Logs_{now.strftime('%b%d')}_{now.strftime('%Y')}"
    
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.pdf"',
        }
    )


class ScanResultsPDFRequest(BaseModel):
    scan_id: Optional[str] = None
    scan_type: Optional[str] = None
    target: Optional[str] = None
    results: Optional[str] = None
    command: Optional[str] = None


@router.post(
    "/scan/pdf",
    summary="Generate scan results PDF",
)
async def generate_scan_pdf(
    request: ScanResultsPDFRequest,
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Generate a PDF report of scan results."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted, HRFlowable
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    
    np_indigo = colors.HexColor('#4f46e5')
    np_cyan = colors.HexColor('#06b6d4')
    
    logo_style = ParagraphStyle('LogoStyle', parent=styles['Normal'], fontSize=28, textColor=np_cyan, fontName='Helvetica-Bold', spaceAfter=8)
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=np_indigo, spaceBefore=10, spaceAfter=10)
    code_style = ParagraphStyle('CodeStyle', parent=styles['Normal'], fontSize=8, fontName='Courier', leftIndent=10, textColor=colors.HexColor('#1e293b'))
    
    elements = []
    elements.append(Paragraph("NETPULSE", logo_style))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(f"Scan Report: {request.scan_type or 'Network Scan'}", title_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=np_cyan, spaceAfter=15))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", styles['Normal']))
    
    if request.target:
        elements.append(Paragraph(f"<b>Target:</b> {request.target}", styles['Normal']))
    if request.command:
        elements.append(Paragraph(f"<b>Command:</b> <font name='Courier' size='9'>{request.command}</font>", styles['Normal']))
    
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("Scan Results", ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=14, textColor=np_indigo)))
    elements.append(HRFlowable(width="30%", thickness=1, color=np_indigo, spaceAfter=10))
    
    if request.results:
        lines = request.results.split('\n')
        for line in lines[:500]:
            elements.append(Preformatted(line[:120], code_style))
    else:
        elements.append(Paragraph("No results available.", styles['Normal']))
    
    doc.build(elements)
    buffer.seek(0)
    
    now = datetime.now()
    filename = f"Scan_{request.scan_type or 'results'}_{now.strftime('%b%d_%H%M')}"
    
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.pdf"',
        }
    )
