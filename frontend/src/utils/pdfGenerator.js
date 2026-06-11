import jsPDF from 'jspdf';
import 'jspdf-autotable';

export const generatePDFReport = (result, isEs) => {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  let yPos = 20;

  // Helpers
  const addTitle = (text, size = 16, color = [41, 128, 185], yOffset = 10) => {
    doc.setFontSize(size);
    doc.setTextColor(...color);
    doc.setFont('helvetica', 'bold');
    if (yPos + yOffset > pageHeight - 20) { doc.addPage(); yPos = 20; }
    doc.text(text, 14, yPos);
    yPos += yOffset;
  };

  const addText = (text, size = 10, isBold = false, xOffset = 14) => {
    if (!text) return;
    doc.setFontSize(size);
    doc.setTextColor(60, 60, 60);
    doc.setFont('helvetica', isBold ? 'bold' : 'normal');
    
    const lines = doc.splitTextToSize(String(text), pageWidth - xOffset - 14);
    if (yPos + (lines.length * 5) > pageHeight - 20) { doc.addPage(); yPos = 20; }
    
    doc.text(lines, xOffset, yPos);
    yPos += lines.length * 5;
  };

  // 1. HEADER
  doc.setFillColor(30, 41, 59);
  doc.rect(0, 0, pageWidth, 40, 'F');
  
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text('VK Scanner Report', 14, 20);
  
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text(`Scan ID: ${result.scan_id || 'Unknown'}`, 14, 28);
  doc.text(`Date: ${new Date(result.timestamp).toLocaleString()}`, 14, 33);
  
  yPos = 50;

  // 2. TARGET & SCORE
  addTitle(isEs ? 'Resumen Ejecutivo' : 'Executive Summary', 16, [15, 23, 42]);
  
  const scoreColor = result.risk_score >= 70 ? [220, 38, 38] : result.risk_score >= 35 ? [217, 119, 6] : [22, 163, 74];
  doc.setFontSize(14);
  doc.setTextColor(...scoreColor);
  doc.text(`Risk Score: ${result.risk_score.toFixed(1)}/100  [${result.classification}]`, 14, yPos);
  yPos += 8;

  addText(`Target: ${result.target}`, 11, true);
  yPos += 2;
  addText(result.summary, 10);
  yPos += 10;

  // 3. IOCs (Indicators of Compromise)
  addTitle(isEs ? 'Indicadores de Compromiso (IoCs)' : 'Indicators of Compromise (IoCs)', 14, [15, 23, 42]);
  
  const iocs = result.iocs || {};
  const hasIocs = (iocs.urls?.length > 0) || (iocs.ips?.length > 0) || (iocs.emails?.length > 0) || (iocs.domains?.length > 0) || (iocs.hashes?.length > 0);

  if (hasIocs) {
    const iocData = [];
    if (iocs.urls) iocs.urls.forEach(u => iocData.push(['URL', u]));
    if (iocs.domains) iocs.domains.forEach(d => iocData.push(['Domain', d]));
    if (iocs.ips) iocs.ips.forEach(ip => iocData.push(['IP', ip]));
    if (iocs.emails) iocs.emails.forEach(e => iocData.push(['Email', e]));
    if (iocs.hashes) iocs.hashes.forEach(h => iocData.push(['Hash', h]));

    doc.autoTable({
      startY: yPos,
      head: [['Type', 'Indicator']],
      body: iocData,
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59] },
      styles: { fontSize: 9, cellPadding: 2, overflow: 'linebreak' },
      columnStyles: { 0: { cellWidth: 30 }, 1: { cellWidth: 'auto' } }
    });
    yPos = doc.lastAutoTable.finalY + 10;
  } else {
    addText(isEs ? 'No se detectaron IoCs.' : 'No IoCs detected.', 10, false);
    yPos += 5;
  }

  // 4. FINDINGS
  addTitle(isEs ? 'Hallazgos Detallados' : 'Detailed Findings', 14, [15, 23, 42]);
  
  if (result.findings && result.findings.length > 0) {
    const findingsData = result.findings.map(f => [
      f.severity,
      f.title,
      f.description
    ]);

    doc.autoTable({
      startY: yPos,
      head: [['Severity', 'Title', 'Description']],
      body: findingsData,
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59] },
      styles: { fontSize: 9, cellPadding: 2 },
      columnStyles: { 
        0: { cellWidth: 25 }, 
        1: { cellWidth: 50 }, 
        2: { cellWidth: 'auto' } 
      },
      didParseCell: function(data) {
        if (data.section === 'body' && data.column.index === 0) {
          if (data.cell.raw === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
          else if (data.cell.raw === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
          else if (data.cell.raw === 'MEDIUM') data.cell.styles.textColor = [217, 119, 6];
          else if (data.cell.raw === 'LOW') data.cell.styles.textColor = [22, 163, 74];
        }
      }
    });
    yPos = doc.lastAutoTable.finalY + 10;
  } else {
    addText(isEs ? 'No se detectaron hallazgos.' : 'No findings detected.', 10, false);
    yPos += 5;
  }

  // 5. METADATA / EXTRA INFO (Optional)
  if (result.document_file_metadata || result.email_extracted_headers) {
    addTitle(isEs ? 'Metadatos del Objetivo' : 'Target Metadata', 14, [15, 23, 42]);
    const metaData = [];
    
    if (result.document_file_metadata) {
      Object.keys(result.document_file_metadata).forEach(file => {
        const meta = result.document_file_metadata[file];
        Object.keys(meta).forEach(k => metaData.push([`${file} - ${k}`, String(meta[k])]));
      });
    }
    
    if (result.email_extracted_headers) {
      Object.keys(result.email_extracted_headers).forEach(k => {
        if (k !== 'Raw') {
          metaData.push([`Email - ${k}`, String(result.email_extracted_headers[k])]);
        }
      });
    }

    if (metaData.length > 0) {
      doc.autoTable({
        startY: yPos,
        head: [['Property', 'Value']],
        body: metaData,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59] },
        styles: { fontSize: 8, cellPadding: 2, overflow: 'linebreak' },
        columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 'auto' } }
      });
      yPos = doc.lastAutoTable.finalY + 10;
    }
  }

  // Save the PDF
  const safeTarget = (result.target || 'scan').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30);
  doc.save(`VKScanner_Report_${safeTarget}.pdf`);
};
