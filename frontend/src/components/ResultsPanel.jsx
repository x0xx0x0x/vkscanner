import React, { useState } from 'react';
import RiskGauge from './RiskGauge';
import FindingCard from './FindingCard';
import DebugPanel from './DebugPanel';
import EmailScanResults from './EmailScanResults';

// Copy components
function CopyButton({ text, label = "COPY", isDefanged = false }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button 
      onClick={handleCopy}
      style={{
        background: isDefanged ? 'rgba(245, 158, 11, 0.1)' : 'rgba(6, 182, 212, 0.1)',
        border: `1px solid ${isDefanged ? 'rgba(245, 158, 11, 0.3)' : 'rgba(6, 182, 212, 0.3)'}`,
        color: isDefanged ? '#fcd34d' : 'var(--cyan)',
        borderRadius: '4px',
        padding: '2px 6px',
        fontSize: '9px',
        cursor: 'pointer',
        fontWeight: 'bold',
        marginLeft: '6px'
      }}
      title={`Copy ${isDefanged ? 'Defanged' : 'Normal'} to Clipboard`}
    >
      {copied ? '✓ COPIED' : label}
    </button>
  );
}

function CopyUrlGroup({ url }) {
  const defanged = url.replace(/http/gi, 'hxxp').replace(/\./g, '[.]');
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center' }}>
      <CopyButton text={url} label="COPY URL" />
      <CopyButton text={defanged} label="DEFANGED" isDefanged={true} />
    </span>
  );
}

// ZIP-Aware Recursive Tree View Component
function AttachmentTree({ tree, getFileStatus, isEs }) {
  if (!tree || tree.length === 0) return null;
  
  const renderNode = (node, depth = 0) => {
    const isZip = node.name.toLowerCase().endsWith('.zip');
    const isDir = node.type === 'directory';
    const hasChildren = node.children && node.children.length > 0;
    const status = getFileStatus && !isDir ? getFileStatus(node.name) : null;
    
    return (
      <div key={node.name} style={{ marginLeft: `${depth * 24}px`, marginTop: '8px', position: 'relative', maxWidth: '100%' }}>
        {depth > 0 && (
          <div style={{
            position: 'absolute',
            left: '-14px',
            top: '-8px',
            bottom: hasChildren ? '0px' : '14px',
            width: '1px',
            borderLeft: '1px dashed rgba(6, 182, 212, 0.25)'
          }} />
        )}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', maxWidth: '100%' }}>
          {depth > 0 && (
            <span style={{ color: 'rgba(6, 182, 212, 0.4)', fontFamily: 'monospace', marginRight: '2px' }}>└──</span>
          )}
          <span style={{ fontSize: '16px' }}>
            {isZip ? '📦' : isDir ? '📁' : '📄'}
          </span>
          <span style={{ 
            fontFamily: 'var(--font-mono)', 
            fontWeight: depth === 0 ? '700' : '400',
            color: 'var(--text-primary)',
            fontSize: '13px',
            wordBreak: 'break-all'
          }}>
            {node.name}
          </span>
          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
            ({(node.size / 1024).toFixed(1)} KB)
          </span>
          {node.type && node.type !== 'file' && node.type !== 'directory' && (
            <span className="badge badge--info" style={{ fontSize: '9px', padding: '1px 6px', opacity: 0.8 }}>
              {node.type}
            </span>
          )}
          {status && (
            <span 
              onClick={() => {
                const el = document.getElementById('findings-section');
                if (el) el.scrollIntoView({ behavior: 'smooth' });
              }}
              style={{ 
              fontSize: '10px', 
              fontWeight: 'bold', 
              color: status.color, 
              marginLeft: '8px',
              padding: '1px 6px',
              background: 'rgba(255, 255, 255, 0.03)',
              border: `1px solid ${status.color}33`,
              borderRadius: '4px',
              display: 'inline-flex',
              alignItems: 'center',
              cursor: 'pointer'
            }}
            title={isEs ? 'Clic para ir a la evidencia maliciosa' : 'Click to go to malicious evidence'}>
              {status.label}
            </span>
          )}
        </div>
        {node.children && node.children.length > 0 && (
          <div style={{ marginBottom: '4px' }}>
            {node.children.map(child => renderNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
      {tree.map(node => renderNode(node))}
    </div>
  );
}

/**
 * Full results panel showing score, findings, breakdown, and debug.
 */
export default function ResultsPanel({ result: rawResult, t }) {
  const [activeResultIdx, setActiveResultIdx] = useState(0);
  const [activeTab, setActiveTab] = useState("summary");
  const [expandedPreview, setExpandedPreview] = useState(null);
  const [expandedChecks, setExpandedChecks] = useState(null);
  const [expandedMetadata, setExpandedMetadata] = useState(null);
  const [expandedDeobfuscated, setExpandedDeobfuscated] = useState(null);
  const [expandedStrings, setExpandedStrings] = useState(null);
  const [previewTab, setPreviewTab] = useState({});
  const [fullCodeExpanded, setFullCodeExpanded] = useState({});
  const [showHeadersCard, setShowHeadersCard] = useState(false);
  const [showIpsCard, setShowIpsCard] = useState(false);
  const [showUrlsCard, setShowUrlsCard] = useState(false);
  const [showEmailsCard, setShowEmailsCard] = useState(false);
  const [showAttachmentsCard, setShowAttachmentsCard] = useState(false);
  const [zoomLevel, setZoomLevel] = useState(1.0);

  // New Collapsible cards states
  const [showSummaryCard, setShowSummaryCard] = useState(true);
  const [showFilesTableCard, setShowFilesTableCard] = useState(true);
  const [showScreenshotCard, setShowScreenshotCard] = useState(true);
  const [showVtCard, setShowVtCard] = useState(true);
  const [showOuterForensics, setShowOuterForensics] = useState(true);
  const [showConfirmedFindings, setShowConfirmedFindings] = useState(true);
  const [showSuspiciousFindings, setShowSuspiciousFindings] = useState(true);
  const [showInfoFindings, setShowInfoFindings] = useState(true);
  const [showMetadataCard, setShowMetadataCard] = useState(true);
  const [showUrlscanCard, setShowUrlscanCard] = useState(true);
  const [showBreakdownCard, setShowBreakdownCard] = useState(true);

  const handleZoomIn = () => setZoomLevel(prev => Math.min(prev + 0.2, 3.0));
  const handleZoomOut = () => setZoomLevel(prev => Math.max(prev - 0.2, 0.5));
  const handleZoomReset = () => setZoomLevel(1.0);

  const renderZoomControls = () => (
    <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '12px', background: 'rgba(2, 6, 23, 0.6)', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)', width: 'fit-content' }}>
      <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>🔍 Zoom:</span>
      <button onClick={handleZoomOut} style={{ padding: '2px 8px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)', borderRadius: '4px', color: 'var(--text-secondary)', cursor: 'pointer' }}>➖</button>
      <span style={{ fontSize: '12px', color: 'var(--text-primary)', width: '40px', textAlign: 'center' }}>{Math.round(zoomLevel * 100)}%</span>
      <button onClick={handleZoomIn} style={{ padding: '2px 8px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)', borderRadius: '4px', color: 'var(--text-secondary)', cursor: 'pointer' }}>➕</button>
      <button onClick={handleZoomReset} style={{ padding: '2px 8px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)', borderRadius: '4px', color: 'var(--cyan)', fontSize: '11px', cursor: 'pointer' }}>Reset</button>
    </div>
  );


  React.useEffect(() => {
    setActiveResultIdx(0);
    setZoomLevel(1.0);
  }, [rawResult]);

  if (!rawResult) return null;

  const result = Array.isArray(rawResult) ? rawResult[activeResultIdx] : rawResult;
  if (!result) return null;

  const isEs = t?.scan_button === 'Escanear';

  const getThreatTags = () => {
    if (!result.findings) return [];
    const text = JSON.stringify(result.findings).toLowerCase();
    const tags = new Set();
    
    if (text.includes('phishing')) tags.add('🎣 PHISHING');
    if (text.includes('ransomware')) tags.add('🔒 RANSOMWARE');
    if (text.includes('spam') || text.includes('marketing')) tags.add('📢 SPAM');
    if (text.includes('bec') || text.includes('business email compromise')) tags.add('💼 BEC');
    if (text.includes('homoglyph') || text.includes('typosquat')) tags.add('🔤 TYPOSQUATTING');
    if (text.includes('quishing') || text.includes('qr')) tags.add('📱 QUISHING');
    if (text.includes('malware') || text.includes('payload')) tags.add('🦠 MALWARE');
    
    if (tags.size === 0) {
      if (result.risk_score >= 70) tags.add('🚨 MALICIOUS');
      else if (result.risk_score >= 35) tags.add('⚠️ SUSPICIOUS');
      else tags.add('🟢 NORMAL');
    }
    return Array.from(tags);
  };
  const threatTags = getThreatTags();

  const getFileStatus = (filename) => {
    if (!filename) return null;
    
    // 1. Check third-party VirusTotal attachment reputation
    const vtData = result.third_party_results?.vt_attachments?.[filename];
    if (vtData) {
      if (vtData.found) {
        if (vtData.malicious_count > 0) {
          return { 
            label: `🔴 VT: ${vtData.score} (${vtData.threat_label || 'Malicious'})`, 
            color: 'var(--risk-high)' 
          };
        }
        return { 
          label: isEs ? `🟢 VT: Limpio` : `🟢 VT: Clean`, 
          color: 'var(--risk-low)' 
        };
      }
    }

    // 2. Check local forensic findings
    const statusInfo = getFindingsForFile(filename);
    if (statusInfo.total === 0) {
      return { label: isEs ? '🟢 Limpio' : '🟢 Clean', color: 'var(--risk-low)' };
    } else if (statusInfo.critical > 0) {
      return { label: isEs ? '🔴 MALICIOSO' : '🔴 MALICIOUS', color: 'var(--risk-high)' };
    } else {
      return { label: isEs ? '⚠️ SOSPECHOSO' : '⚠️ SUSPICIOUS', color: 'var(--risk-medium)' };
    }
  };

  const getUrlStatus = (url) => {
    if (!url) return null;
    const isFlagged = (result.findings || []).some(f => {
      const ev = (f.evidence || '').toLowerCase();
      const ds = (f.description || '').toLowerCase();
      const title = (f.title || '').toLowerCase();
      const targetUrl = url.toLowerCase();
      return ev.includes(targetUrl) || ds.includes(targetUrl) || title.includes(targetUrl);
    });
    
    if (isFlagged) {
      return { label: isEs ? '🔴 MALICIOSO / RIESGO' : '🔴 MALICIOUS / THREAT', color: 'var(--risk-high)' };
    }
    
    const urlscanData = result.third_party_results?.urlscan_urls?.[url];
    if (urlscanData) {
      if (urlscanData.success) {
        return { label: isEs ? '🟢 Limpio (urlscan.io)' : '🟢 Clean (urlscan.io)', color: 'var(--risk-low)' };
      } else if (urlscanData.error) {
        return { label: isEs ? '⚪ Error de Consulta' : '⚪ Lookup Error', color: 'var(--text-secondary)' };
      }
    }
    
    return { label: isEs ? '🟢 Limpio (Heurística Local)' : '🟢 Clean (Local Heuristic)', color: 'var(--risk-low)' };
  };

  const handleDownloadJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(result, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `vkscanner_report_${result.scan_id}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  const handleDownloadReport = () => {
    const printWindow = window.open('', '_blank');
    if (!printWindow) {
      alert('Error opening print window. Please allow popups.');
      return;
    }

    const dateStr = new Date(result.timestamp).toLocaleString();

    const sevBadge = (sev) => {
      const colors = {
        critical: '#be123c',
        high: '#e11d48',
        medium: '#d97706',
        low: '#10b981',
        info: '#3b82f6'
      };
      return `<span style="padding: 2px 6px; border-radius: 4px; font-weight: bold; background: ${colors[sev] || '#64748b'}; color: white; font-size: 11px;">${sev.toUpperCase()}</span>`;
    };

    const findingsRows = (result.findings || []).map(f => `
      <tr>
        <td style="padding: 8px; border: 1px solid #cbd5e1; font-family: monospace; font-size: 11px;">${f.category}</td>
        <td style="padding: 8px; border: 1px solid #cbd5e1;">
          <strong>${f.title}</strong><br/>
          <span style="font-size: 11px; color: #475569;">${f.description}</span>
          ${f.evidence ? `<br/><div style="margin-top: 4px; padding: 4px 8px; background: #f1f5f9; border-left: 2px solid #64748b; font-family: monospace; font-size: 10px; color: #334155; word-break: break-all;">Evidence: ${f.evidence}</div>` : ''}
        </td>
        <td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center;">${sevBadge(f.severity)}</td>
        <td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; font-family: monospace;">${f.score_impact > 0 ? '+' : ''}${f.score_impact}</td>
      </tr>
    `).join('');

    const traceRows = (result.debug_trace || []).map(dt => `
      <tr>
        <td style="padding: 6px; border: 1px solid #e2e8f0; font-family: monospace; font-size: 10px; color: #64748b;">${new Date(dt.timestamp).toLocaleTimeString()}</td>
        <td style="padding: 6px; border: 1px solid #e2e8f0; font-family: monospace; font-weight: bold; font-size: 10px; color: #0f172a;">${dt.analyzer}</td>
        <td style="padding: 6px; border: 1px solid #e2e8f0; font-size: 11px; color: #334155;">
          <strong>${dt.action}</strong>${dt.detail ? ` - <span style="font-family: monospace; font-size: 10px; color: #475569;">${dt.detail}</span>` : ''}
        </td>
        <td style="padding: 6px; border: 1px solid #e2e8f0; text-align: center; font-family: monospace; font-size: 10px;">${dt.result || 'OK'}</td>
      </tr>
    `).join('');

    // Generate technical metadata and cryptographic signatures
    const buildMetadataTableHtml = () => {
      if (!result.document_file_metadata || Object.keys(result.document_file_metadata).length === 0) return '';
      let html = `<h2 class="section-title">${isEs ? 'Metadatos Técnicos y Firmas Criptográficas (Metadata)' : 'Cryptographic Hashing & File Metadata'}</h2>`;
      
      Object.entries(result.document_file_metadata).forEach(([filename, meta]) => {
        html += `
          <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 18px; margin-bottom: 25px; page-break-inside: avoid;">
            <h4 style="margin-top: 0; margin-bottom: 12px; font-size: 13px; color: #0f172a; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; font-family: monospace;">
              📄 ${isEs ? 'Archivo' : 'File'}: <strong>${filename}</strong>
            </h4>
            <table style="width: 100%; border-collapse: collapse; margin-bottom: 5px; font-size: 11px;">
              <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 6px 8px; font-weight: bold; background: #f1f5f9; width: 25%;">${isEs ? 'Autor / Creador' : 'Author / Creator'}</td>
                <td style="padding: 6px 8px; color: #1e293b;">${meta.author || 'Unknown'}</td>
                <td style="padding: 6px 8px; font-weight: bold; background: #f1f5f9; width: 25%;">${isEs ? 'Tamaño' : 'File Size'}</td>
                <td style="padding: 6px 8px; color: #1e293b; font-family: monospace;">${meta.file_size_bytes ? `${meta.file_size_bytes.toLocaleString()} bytes` : 'N/A'}</td>
              </tr>
              <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 6px 8px; font-weight: bold; background: #f1f5f9;">${isEs ? 'Fecha de Creación' : 'Created Date'}</td>
                <td style="padding: 6px 8px; color: #1e293b; font-family: monospace;">${meta.created_at || 'N/A'}</td>
                <td style="padding: 6px 8px; font-weight: bold; background: #f1f5f9;">${isEs ? 'Última Modificación' : 'Last Modified'}</td>
                <td style="padding: 6px 8px; color: #1e293b; font-family: monospace;">${meta.last_modified || 'N/A'}</td>
              </tr>
              <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 6px 8px; font-weight: bold; background: #f1f5f9;">SHA-256 Hash</td>
                <td colspan="3" style="padding: 6px 8px; color: #0284c7; font-family: monospace; font-weight: bold; word-break: break-all;">${meta.sha256 || 'N/A'}</td>
              </tr>
              <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 6px 8px; font-weight: bold; background: #f1f5f9;">MD5 Hash</td>
                <td colspan="3" style="padding: 6px 8px; color: #4f46e5; font-family: monospace; word-break: break-all;">${meta.md5 || 'N/A'}</td>
              </tr>
              <tr>
                <td style="padding: 6px 8px; font-weight: bold; background: #f1f5f9;">SHA-512 Hash</td>
                <td colspan="3" style="padding: 6px 8px; color: #475569; font-family: monospace; word-break: break-all; font-size: 10px;">${meta.sha512 || 'N/A'}</td>
              </tr>
            </table>
          </div>
        `;
      });
      return html;
    };

    // Generate checklist tables per analyzed file to show comprehensive security check results
    const buildChecklistsHtml = () => {
      if (!result.document_file_checks || Object.keys(result.document_file_checks).length === 0) return '';
      let html = `<h2 class="section-title">${isEs ? 'Detalle de Auditoría de Seguridad por Archivo (Checklists)' : 'Security Checklists per Analyzed File'}</h2>`;
      
      Object.entries(result.document_file_checks).forEach(([filename, checks]) => {
        if (!checks || checks.length === 0) return;
        const fileMeta = result.document_file_metadata?.[filename] || {};
        const fileCtx = result.document_file_contexts?.[filename];
        
        html += `
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 20px; page-break-inside: avoid;">
            <h3 style="margin-top: 0; margin-bottom: 12px; font-size: 13px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: monospace; display: flex; justify-content: space-between; align-items: center;">
              <span>📄 File: <strong>${filename}</strong></span>
              ${fileCtx ? `<span style="font-size: 10px; font-weight: normal; color: #4f46e5; background: #e0e7ff; padding: 2px 8px; border-radius: 4px;">🧠 ${fileCtx}</span>` : ''}
            </h3>
            <table style="width: 100%; border-collapse: collapse; margin-bottom: 10px; font-size: 11px;">
              <thead>
                <tr style="background: #f1f5f9;">
                  <th style="padding: 6px 8px; border: 1px solid #cbd5e1; text-align: left; width: 60%;">${isEs ? 'Regla / Firma de Seguridad Evaluada' : 'Security Rule Checked'}</th>
                  <th style="padding: 6px 8px; border: 1px solid #cbd5e1; text-align: center; width: 40%;">${isEs ? 'Resultado' : 'Outcome'}</th>
                </tr>
              </thead>
              <tbody>
        `;
        
        checks.forEach(check => {
          const outcomeText = check.found 
            ? (isEs ? '🚨 DETECTADO / SOSPECHOSO' : '🚨 DETECTED / THREAT') 
            : (isEs ? '🟢 LIMPIO / SEGURO' : '🟢 CLEAN / NOT FOUND');
          const color = check.found ? '#b91c1c' : '#15803d';
          const bg = check.found ? '#fef2f2' : '#f0fdf4';
          html += `
            <tr>
              <td style="padding: 6px 8px; border: 1px solid #cbd5e1;">${check.name}</td>
              <td style="padding: 6px 8px; border: 1px solid #cbd5e1; text-align: center; font-weight: bold; color: ${color}; background: ${bg};">${outcomeText}</td>
            </tr>
          `;
        });
        
        html += `
              </tbody>
            </table>
        `;
        
        html += `</div>`;
      });
      
      return html;
    };

    // Generate code previews and deobfuscation tables for deep inspection
    const buildPreviewsHtml = () => {
      const previews = result.document_file_previews || {};
      const deobfs = result.document_file_deobfuscated || {};
      if (Object.keys(previews).length === 0 && Object.keys(deobfs).length === 0) return '';
      
      let html = `<h2 class="section-title">${isEs ? 'Análisis de Código y Desofuscación Profunda' : 'Code Inspection & Deobfuscation Findings'}</h2>`;
      
      // Deobfuscations
      Object.entries(deobfs).forEach(([filename, payloads]) => {
        if (!payloads || payloads.length === 0) return;
        html += `
          <div style="background: #fffbeb; border: 1px solid #fef3c7; border-radius: 8px; padding: 16px; margin-bottom: 20px; page-break-inside: avoid;">
            <h3 style="margin-top: 0; margin-bottom: 12px; font-size: 13px; color: #b45309; border-bottom: 1px solid #fde68a; padding-bottom: 6px; font-family: monospace;">
              🔓 ${isEs ? 'Cadenas Desofuscadas' : 'Deobfuscated Payloads'} - ${filename}
            </h3>
        `;
        payloads.forEach((p, idx) => {
          html += `
            <div style="margin-bottom: 12px; font-size: 11px;">
              <div style="font-weight: bold; color: #92400e; margin-bottom: 4px;">Payload #${idx + 1} - Encoding Type: ${p.type}</div>
              <div style="background: #fffbeb; border: 1px solid #fcd34d; border-radius: 4px; padding: 6px 10px; font-family: monospace; font-size: 10px; white-space: pre-wrap; word-break: break-all; margin-bottom: 4px;">
                <span style="color: #b45309; font-weight: bold;">[Raw]:</span> ${p.raw}
              </div>
              <div style="background: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 4px; padding: 6px 10px; font-family: monospace; font-size: 10px; white-space: pre-wrap; word-break: break-all; color: #065f46;">
                <span style="color: #047857; font-weight: bold;">[Decoded]:</span> ${p.decoded}
              </div>
            </div>
          `;
        });
        html += `</div>`;
      });

      // Code previews
      Object.entries(previews).forEach(([filename, content]) => {
        if (!content) return;
        html += `
          <div style="background: #fafafa; border: 1px solid #e5e5e5; border-radius: 8px; padding: 16px; margin-bottom: 20px; page-break-inside: avoid;">
            <h3 style="margin-top: 0; margin-bottom: 8px; font-size: 13px; color: #333; border-bottom: 1px solid #e5e5e5; padding-bottom: 6px; font-family: monospace;">
              🔍 ${isEs ? 'Fragmento de Código Analizado' : 'Analyzed Code Snippet'} - ${filename}
            </h3>
            <pre style="background: #0f172a; color: #f8fafc; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 10px; max-height: 250px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; text-align: left; margin: 0; line-height: 1.4;">${content}</pre>
          </div>
        `;
      });
      
      return html;
    };

    // Generate detailed email analysis findings or extracted document elements
    const buildEmailForensicsHtml = () => {
      const hasHeaders = result.email_extracted_headers && Object.keys(result.email_extracted_headers).length > 0;
      const hasIps = result.email_extracted_ips && result.email_extracted_ips.length > 0;
      const hasUrls = result.email_extracted_urls && result.email_extracted_urls.length > 0;
      const hasTree = result.email_attachment_tree && result.email_attachment_tree.length > 0;
      
      if (!hasHeaders && !hasIps && !hasUrls && !hasTree) return '';
      
      const sectionTitle = result.scan_type === 'email'
        ? (isEs ? 'Análisis Forense de Correo e Indicadores' : 'Email Forensics & Forensic Indicators')
        : (isEs ? 'Indicadores Forenses y Enlaces Extraídos' : 'Forensic Indicators & Extracted Links');
      
      let html = `<h2 class="section-title">${sectionTitle}</h2>`;

      // Email Headers
      if (hasHeaders) {
        const eh = result.email_extracted_headers;
        html += `
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 20px; page-break-inside: avoid;">
            <h3 style="margin-top: 0; margin-bottom: 12px; font-size: 13px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">📨 ${isEs ? 'Cabeceras de Correo' : 'Email Headers'}</h3>
            <table style="width: 100%; border-collapse: collapse; font-size: 11px;">
              <tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 6px; font-weight: bold; width: 25%;">From:</td><td style="padding: 6px; font-family: monospace; color: #1e293b;">${eh.From || 'Unknown'}</td></tr>
              <tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 6px; font-weight: bold;">To:</td><td style="padding: 6px; font-family: monospace; color: #1e293b;">${eh.To || 'Unknown'}</td></tr>
              <tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 6px; font-weight: bold;">Subject:</td><td style="padding: 6px; font-weight: bold; color: #0f172a;">${eh.Subject || '(No Subject)'}</td></tr>
              <tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 6px; font-weight: bold;">Date:</td><td style="padding: 6px; color: #1e293b;">${eh.Date || 'N/A'}</td></tr>
              ${eh['Reply-To'] ? `<tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 6px; font-weight: bold;">Reply-To:</td><td style="padding: 6px; font-family: monospace; color: #1e293b;">${eh['Reply-To']}</td></tr>` : ''}
              ${eh['Return-Path'] ? `<tr style="border-bottom: 1px solid #e2e8f0;"><td style="padding: 6px; font-weight: bold;">Return-Path:</td><td style="padding: 6px; font-family: monospace; color: #1e293b;">${eh['Return-Path']}</td></tr>` : ''}
            </table>
          </div>
        `;
      }

      // IP Addresses with Abuse Reputation
      if (result.email_extracted_ips && result.email_extracted_ips.length > 0) {
        html += `
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 20px; page-break-inside: avoid;">
            <h3 style="margin-top: 0; margin-bottom: 12px; font-size: 13px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">🔌 ${isEs ? 'Direcciones IP Detectadas y Reputación de Abuso' : 'IP Reputation Audit (AbuseIPDB)'}</h3>
            <table style="width: 100%; border-collapse: collapse; font-size: 11px;">
              <thead>
                <tr style="background: #f1f5f9;">
                  <th style="padding: 6px; border: 1px solid #cbd5e1; text-align: left;">IP Address</th>
                  <th style="padding: 6px; border: 1px solid #cbd5e1; text-align: left;">Country</th>
                  <th style="padding: 6px; border: 1px solid #cbd5e1; text-align: left;">ISP / Provider</th>
                  <th style="padding: 6px; border: 1px solid #cbd5e1; text-align: center;">Abuse Score</th>
                </tr>
              </thead>
              <tbody>
        `;
        result.email_extracted_ips.forEach(ip => {
          const abuse = result.third_party_results?.abuseipdb_ips?.[ip] || {};
          const score = abuse.score !== undefined ? `${abuse.score}%` : 'N/A';
          const color = abuse.score > 20 ? '#b91c1c' : abuse.score !== undefined ? '#15803d' : '#475569';
          const bg = abuse.score > 20 ? '#fef2f2' : abuse.score !== undefined ? '#f0fdf4' : 'transparent';
          html += `
            <tr>
              <td style="padding: 6px; border: 1px solid #cbd5e1; font-family: monospace; font-weight: bold;">${ip}</td>
              <td style="padding: 6px; border: 1px solid #cbd5e1;">${abuse.country || 'Unknown'}</td>
              <td style="padding: 6px; border: 1px solid #cbd5e1;">${abuse.isp || 'N/A'}</td>
              <td style="padding: 6px; border: 1px solid #cbd5e1; text-align: center; font-weight: bold; color: ${color}; background: ${bg};">${score}</td>
            </tr>
          `;
        });
        html += `
              </tbody>
            </table>
          </div>
        `;
      }

      // Discovered URLs
      if (result.email_extracted_urls && result.email_extracted_urls.length > 0) {
        html += `
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 20px; page-break-inside: avoid;">
            <h3 style="margin-top: 0; margin-bottom: 12px; font-size: 13px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">🔗 ${isEs ? 'Enlaces URL Detectados y Análisis Sandbox' : 'Extracted Links & Sandbox Status'}</h3>
            <table style="width: 100%; border-collapse: collapse; font-size: 11px;">
              <thead>
                <tr style="background: #f1f5f9;">
                  <th style="padding: 6px; border: 1px solid #cbd5e1; text-align: left; width: 65%;">URL Link</th>
                  <th style="padding: 6px; border: 1px solid #cbd5e1; text-align: center; width: 35%;">Sandbox Scan Report</th>
                </tr>
              </thead>
              <tbody>
        `;
        result.email_extracted_urls.forEach(url => {
          const urlscan = result.third_party_results?.urlscan_urls?.[url] || {};
          const urlscanText = urlscan.result_url 
            ? `<a href="${urlscan.result_url}" target="_blank" style="color: #2563eb; text-decoration: none;">urlscan.io Report ↗</a>` 
            : (isEs ? 'No se ejecutó escaneo sandbox' : 'No sandbox scan triggered');
          html += `
            <tr>
              <td style="padding: 6px; border: 1px solid #cbd5e1; font-family: monospace; word-break: break-all;">${url}</td>
              <td style="padding: 6px; border: 1px solid #cbd5e1; text-align: center;">${urlscanText}</td>
            </tr>
          `;
        });
        html += `
              </tbody>
            </table>
          </div>
        `;
      }

      // Attachment Tree
      if (result.email_attachment_tree && result.email_attachment_tree.length > 0) {
        const renderTextNode = (node, depth = 0) => {
          const indent = '&nbsp;'.repeat(depth * 4);
          const prefix = depth > 0 ? '└── ' : '';
          const icon = node.name.toLowerCase().endsWith('.zip') ? '📦' : node.type === 'directory' ? '📁' : '📄';
          let res = `<div style="font-family: monospace; font-size: 11px; margin-top: 4px; padding-left: 8px; line-height: 1.4; word-break: break-all;">
            ${indent}${prefix}${icon} <strong>${node.name}</strong> (${(node.size / 1024).toFixed(1)} KB) <span style="color: #64748b;">[Type: ${node.type || 'file'}]</span>
          </div>`;
          if (node.children && node.children.length > 0) {
            node.children.forEach(child => {
              res += renderTextNode(child, depth + 1);
            });
          }
          return res;
        };

        html += `
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 20px; page-break-inside: avoid;">
            <h3 style="margin-top: 0; margin-bottom: 12px; font-size: 13px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">📎 ${isEs ? 'Estructura de Archivos Adjuntos' : 'Email Attachments Recursive Structure Tree'}</h3>
            <div style="padding: 10px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 4px;">
        `;
        result.email_attachment_tree.forEach(node => {
          html += renderTextNode(node);
        });
        html += `
            </div>
          </div>
        `;
      }

      return html;
    };

    const htmlContent = `
      <html>
        <head>
          <title>VK Scanner Forensic Report - ${result.target}</title>
          <style>
            body {
              font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
              color: #0f172a;
              margin: 40px;
              line-height: 1.5;
              background-color: #ffffff;
            }
            .header-table {
              width: 100%;
              border-collapse: collapse;
              margin-bottom: 25px;
            }
            .brand-logo {
              font-size: 28px;
              font-weight: 900;
              color: #0f172a;
              border-bottom: 4px solid #0f172a;
              padding-bottom: 10px;
              letter-spacing: 1px;
            }
            .report-title {
              font-size: 16px;
              font-weight: bold;
              text-transform: uppercase;
              text-align: right;
              border-bottom: 4px solid #cbd5e1;
              padding-bottom: 10px;
              color: #475569;
              letter-spacing: 0.5px;
            }
            .meta-card {
              background: #f8fafc;
              border: 1px solid #e2e8f0;
              border-radius: 8px;
              padding: 20px;
              margin-bottom: 30px;
            }
            .meta-grid {
              display: grid;
              grid-template-columns: repeat(2, 1fr);
              gap: 15px;
            }
            .meta-item {
              font-size: 12px;
            }
            .meta-label {
              color: #64748b;
              text-transform: uppercase;
              font-size: 9px;
              font-weight: bold;
              display: block;
              margin-bottom: 4px;
            }
            .status-banner {
              padding: 16px;
              border-radius: 8px;
              text-align: center;
              font-size: 16px;
              font-weight: bold;
              margin-bottom: 30px;
              border: 2px solid;
            }
            .status-banner--critical {
              background: #ffe4e6;
              border-color: #f43f5e;
              color: #be123c;
            }
            .status-banner--medium {
              background: #fef3c7;
              border-color: #f59e0b;
              color: #d97706;
            }
            .status-banner--low {
              background: #d1fae5;
              border-color: #10b981;
              color: #065f46;
            }
            .section-title {
              font-size: 14px;
              text-transform: uppercase;
              letter-spacing: 0.5px;
              border-bottom: 2px solid #e2e8f0;
              padding-bottom: 6px;
              margin-top: 40px;
              margin-bottom: 15px;
              color: #0f172a;
              page-break-before: always;
              break-before: page;
              page-break-after: avoid;
            }
            .section-title--first {
              page-break-before: avoid;
              break-before: avoid;
              margin-top: 20px;
            }
            table {
              width: 100%;
              border-collapse: collapse;
              margin-bottom: 25px;
              font-size: 11px;
              page-break-inside: avoid;
            }
            th {
              background: #f1f5f9;
              color: #475569;
              text-align: left;
              padding: 8px;
              border: 1px solid #cbd5e1;
              font-weight: bold;
            }
            td {
              padding: 8px;
              border: 1px solid #e2e8f0;
            }
            @media print {
              .control-bar { display: none !important; }
              body { margin: 20px; }
              button { display: none; }
            }
          </style>
        </head>
        <body style="margin: 0; padding: 0;">
          <!-- Interactive control bar for viewing in browser and manual printing -->
          <div class="control-bar" style="background: #0f172a; padding: 12px 24px; color: white; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 1000; border-bottom: 2px solid #1e293b; font-family: sans-serif; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            <div style="font-weight: bold; font-size: 14px; display: flex; align-items: center; gap: 8px;">
              🛡️ VK Scanner — ${isEs ? 'Reporte Forense Digital' : 'Forensic Report Viewer'}
            </div>
            <div style="display: flex; gap: 12px;">
              <button onclick="window.print()" style="background: #06b6d4; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; display: flex; align-items: center; gap: 6px; font-size: 12px; transition: background 0.2s;">
                🖨️ ${isEs ? 'Imprimir / Guardar PDF' : 'Print / Save PDF'}
              </button>
              <button onclick="window.close()" style="background: rgba(255,255,255,0.1); color: white; border: 1px solid rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 12px;">
                ❌ ${isEs ? 'Cerrar Vista' : 'Close View'}
              </button>
            </div>
          </div>

          <div style="padding: 40px;">
            <table class="header-table">
              <tr>
                <td class="brand-logo" style="border: none;">VOIGHT-KAMPFF ANALYZER</td>
                <td class="report-title" style="border: none;">${isEs ? 'Reporte Forense de Seguridad' : 'Forensic Security Report'}</td>
              </tr>
            </table>

            <div class="status-banner ${result.risk_score >= 70 ? 'status-banner--critical' : result.risk_score >= 35 ? 'status-banner--medium' : 'status-banner--low'}">
              ${result.risk_score >= 70 
                ? (isEs ? '🚨 DETECTADA ACTIVIDAD SOSPECHOSA / RIESGO ALTO' : '🚨 SUSPICIOUS ACTIVITY / THREAT DETECTED')
                : result.risk_score >= 35 
                  ? (isEs ? '⚠️ ACTIVIDAD SOSPECHOSA DETECTADA' : '⚠️ SUSPICIOUS ACTIVITY DETECTED')
                  : (isEs ? '🟢 ARCHIVO LIMPIO / SIN COMPORTAMIENTOS MALICIOSOS' : '🟢 CLEAN TARGET / NO SUSPICIOUS BEHAVIORS')}
              (${isEs ? 'Puntaje de Riesgo:' : 'Global Risk Score:'} ${result.risk_score}/100)
            </div>

            <div class="meta-card">
              <div class="meta-grid">
                <div class="meta-item">
                  <span class="meta-label">${isEs ? 'Objetivo Analizado' : 'Scan Target'}</span>
                  <strong style="word-break: break-all;">${result.target}</strong>
                </div>
                <div class="meta-item">
                  <span class="meta-label">ID ${isEs ? 'del Escaneo' : 'Scan ID'}</span>
                  <strong style="font-family: monospace;">${result.scan_id}</strong>
                </div>
                <div class="meta-item">
                  <span class="meta-label">${isEs ? 'Fecha de Escaneo' : 'Analysis Date'}</span>
                  <strong>${dateStr}</strong>
                </div>
                <div class="meta-item">
                  <span class="meta-label">${isEs ? 'Grado de Confianza' : 'Assessment Confidence'}</span>
                  <strong>${result.confidence}%</strong>
                </div>
              </div>
            </div>

            <h2 class="section-title section-title--first">${isEs ? 'Resumen Ejecutivo' : 'Executive Summary'}</h2>
            <p style="font-size: 12px; color: #334155; margin-bottom: 25px; line-height: 1.6;">${result.summary}</p>

          ${buildMetadataTableHtml()}
          ${buildChecklistsHtml()}
          ${buildPreviewsHtml()}
          ${buildEmailForensicsHtml()}

          <h2 class="section-title">${isEs ? 'Detecciones e Indicadores de Compromiso (Findings)' : 'Security Detections & IOCs (Findings)'} (${result.findings?.length || 0})</h2>
          ${result.findings && result.findings.length > 0 ? `
            <table>
              <thead>
                <tr>
                  <th style="width: 15%;">${isEs ? 'Categoría' : 'Category'}</th>
                  <th style="width: 55%;">${isEs ? 'Descripción del Hallazgo' : 'Finding Description'}</th>
                  <th style="width: 15%; text-align: center;">${isEs ? 'Severidad' : 'Severity'}</th>
                  <th style="width: 15%; text-align: center;">${isEs ? 'Impacto' : 'Score Impact'}</th>
                </tr>
              </thead>
              <tbody>
                ${findingsRows}
              </tbody>
            </table>
          ` : `<p style="font-size: 12px; color: #64748b; margin-bottom: 25px;">${isEs ? 'Análisis Completado: No se identificaron firmas de malware, keywords maliciosas ni heurísticas sospechosas en este objetivo.' : 'Analysis Completed: No malware signatures, malicious keywords, or suspicious heuristics were identified in this target.'}</p>`}

          <h2 class="section-title">${isEs ? 'Bitácora Forense y Registro Técnico' : 'Forensic Log & Technical Trace'}</h2>
          <table>
            <thead>
              <tr>
                <th style="width: 12%;">${isEs ? 'Hora' : 'Time'}</th>
                <th style="width: 18%;">${isEs ? 'Analizador' : 'Analyzer'}</th>
                <th style="width: 58%;">${isEs ? 'Acción Ejecutada' : 'Action Performed'}</th>
                <th style="width: 12%; text-align: center;">${isEs ? 'Resultado' : 'Outcome'}</th>
              </tr>
            </thead>
            <tbody>
              ${traceRows}
            </tbody>
          </table>

            <div style="margin-top: 50px; border-top: 1px solid #cbd5e1; padding-top: 15px; text-align: center; font-size: 9px; color: #64748b;">
              VK Scanner v1.0.0 — ${isEs ? 'Firma Forense Digital Automatizada Voight-Kampff' : 'Voight-Kampff Automated Digital Forensic Sign-off'}
            </div>
          </div>
        </body>
      </html>
    `;

    printWindow.document.write(htmlContent);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 450);
  };
  
  // Dynamic parsing of debug trace to construct the detailed file list
  const getAnalyzedFiles = (debugTrace) => {
    const files = [];
    const seen = new Set();
    if (!debugTrace) return files;
    
    debugTrace.forEach(step => {
      const action = step.action || '';
      const detail = step.detail || '';
      
      // 1. Analyzed attachment or inner zip file
      if (action === 'scanning_attachment' || action === 'zip_recursive_scan') {
        let filename = '';
        let type = '';
        
        const fileMatch = detail.match(/(?:Deep-scanning attachment|Extracting and recursively scanning):\s*(.+?)(?:\s*\(Detected type:|$)/i);
        const typeMatch = detail.match(/Detected type:\s*([^\s)]+)/i);
        
        if (fileMatch) filename = fileMatch[1];
        if (typeMatch) type = typeMatch[1];
        
        if (!filename && detail.includes(':')) {
          filename = detail.split(':')[1].split('(')[0].trim();
        }
        
        if (filename && !seen.has(filename)) {
          seen.add(filename);
          files.push({
            name: filename,
            type: type || filename.split('.').pop() || 'unknown',
            status: 'analyzed',
            details: isEs ? 'Escaneado y analizado en el motor forense' : 'Successfully extracted and forensically analyzed'
          });
        }
      }
      
      // 2. Skipped/Omitted attachment
      if (action === 'skip_attachment' || action === 'zip_skip_inner') {
        let filename = '';
        let type = '';
        
        const fileMatch = detail.match(/(?:Omit attachment|Omit inner file):\s*(.+?)(?:\s*\(Unsupported type:|$)/i);
        const typeMatch = detail.match(/Unsupported type:\s*([^\s)]+)/i);
        
        if (fileMatch) filename = fileMatch[1];
        if (typeMatch) type = typeMatch[1];
        
        if (filename && !seen.has(filename)) {
          seen.add(filename);
          files.push({
            name: filename,
            type: type || filename.split('.').pop() || 'unknown',
            status: 'skipped',
            details: isEs ? 'Omitido (Formato no compatible para análisis profundo)' : 'Omitted (Unsupported format for deep analysis)'
          });
        }
      }
      
      // 3. Read error
      if (action === 'zip_read_error') {
        let filename = '';
        const fileMatch = detail.match(/Could not read '([^']+)'/i);
        if (fileMatch) filename = fileMatch[1];
        
        if (filename && !seen.has(filename)) {
          seen.add(filename);
          files.push({
            name: filename,
            type: filename.split('.').pop() || 'unknown',
            status: 'error',
            details: isEs ? 'Error de lectura (Posible archivo dañado o protegido)' : 'Read Error (Corrupted or password-protected file)'
          });
        }
      }
    });
    
    // Add main target file itself if this is a single file scan
    if (files.length === 0 && result.scan_type === 'document') {
      files.push({
        name: result.target,
        type: result.target.split('.').pop() || 'unknown',
        status: 'analyzed',
        details: isEs ? 'Archivo principal analizado con éxito' : 'Main target file analyzed successfully'
      });
    }
    
    return files;
  };

  const analyzedFiles = getAnalyzedFiles(result.debug_trace);

  // Helper to count findings for a specific file to report threat details
  const getFindingsForFile = (filename) => {
    if (!result.findings) return { critical: 0, warning: 0, total: 0 };
    let critical = 0;
    let warning = 0;
    let total = 0;
    const fn = filename.toLowerCase();
    
    result.findings.forEach(f => {
      const ev = (f.evidence || '').toLowerCase();
      const ds = (f.description || '').toLowerCase();
      const title = (f.title || '').toLowerCase();
      
      if (ev.includes(fn) || ds.includes(fn) || title.includes(fn)) {
        total++;
        if (f.severity === 'critical' || f.severity === 'high') {
          critical++;
        } else if (f.severity === 'medium' || f.severity === 'low') {
          warning++;
        }
      }
    });
    
    return { critical, warning, total };
  };

  return (
    <div className="results-panel" id="results-panel">
      {/* File results tab switcher (if multiple files were scanned) */}
      {Array.isArray(rawResult) && rawResult.length > 1 && (
        <div style={{
          display: 'flex',
          gap: '8px',
          overflowX: 'auto',
          paddingBottom: '12px',
          marginBottom: '24px',
          borderBottom: '1px solid var(--border-primary)'
        }}>
          {rawResult.map((res, idx) => {
            const isSelected = idx === activeResultIdx;
            return (
              <button
                key={res.scan_id || idx}
                onClick={() => setActiveResultIdx(idx)}
                style={{
                  background: isSelected ? 'rgba(96, 165, 250, 0.15)' : 'rgba(255, 255, 255, 0.02)',
                  border: isSelected ? '1px solid var(--cyan)' : '1px solid var(--border-subtle)',
                  color: isSelected ? 'var(--text-primary)' : 'var(--text-secondary)',
                  padding: '8px 16px',
                  borderRadius: 'var(--radius-sm)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12px',
                  cursor: 'pointer',
                  fontWeight: isSelected ? 700 : 400,
                  whiteSpace: 'nowrap',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  transition: 'all 0.2s'
                }}
              >
                <span>{res.risk_score >= 70 ? '🔴' : res.risk_score >= 35 ? '⚠️' : '🟢'}</span>
                {res.target}
                <span style={{ fontSize: '10px', opacity: 0.6 }}>({res.risk_score}/100)</span>
              </button>
            );
          })}
        </div>
      )}

      
      <div className="tabs" style={{ marginBottom: '24px' }}>
        <button className={`tabs__btn ${activeTab === 'summary' ? 'tabs__btn--active' : ''}`} onClick={() => setActiveTab('summary')}>📊 {isEs ? 'Resumen' : 'Summary'}</button>
        <button className={`tabs__btn ${activeTab === 'intel' ? 'tabs__btn--active' : ''}`} onClick={() => setActiveTab('intel')}>👁️ {isEs ? 'Inteligencia Externa' : 'External Intel'}</button>
        <button className={`tabs__btn ${activeTab === 'forensics' ? 'tabs__btn--active' : ''}`} onClick={() => setActiveTab('forensics')}>🌐 {isEs ? 'Red y Forense' : 'Forensics & IoCs'}</button>
      </div>

      <div style={{ display: activeTab === "summary" ? "block" : "none" }}>

      {/* 1. Key Metadata Card displayed first */}
      {((result.document_file_metadata && Object.keys(result.document_file_metadata).length > 0) || result.email_extracted_headers) && (
        <div style={{ marginBottom: '24px' }}>
          <div 
            onClick={() => setShowMetadataCard(!showMetadataCard)}
            className="results-panel__section-title"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', userSelect: 'none' }}
          >
            <span>📋 {isEs ? 'Metadatos Claves del Objetivo' : 'Target Key Metadata'}</span>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 'normal' }}>
              {showMetadataCard ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
            </span>
          </div>
          {showMetadataCard && (
            <div className="card" style={{
              background: 'rgba(23, 28, 38, 0.4)',
              border: '1px solid var(--border-primary)',
              padding: '16px 20px',
              borderRadius: 'var(--radius-md)',
              fontSize: '13px',
            }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', textAlign: 'left' }}>
              <div>
                <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>
                  {isEs ? 'Objetivo Analizado' : 'Scanned Target'}
                </span>
                <strong style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all', color: 'var(--text-primary)' }}>{result.target}</strong>
              </div>
              
              {/* If it is a document, show its size & author */}
              {(() => {
                const metaList = result.document_file_metadata ? Object.values(result.document_file_metadata) : [];
                if (metaList.length > 0) {
                  const m = metaList[0];
                  return (
                    <>
                      <div>
                        <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>
                          {isEs ? 'Tamaño del Archivo' : 'File Size'}
                        </span>
                        <strong style={{ color: 'var(--text-primary)' }}>{m.file_size_bytes ? `${(m.file_size_bytes / 1024).toFixed(1)} KB` : 'N/A'}</strong>
                      </div>
                      {m.author && m.author !== 'Unknown' && (
                        <div>
                          <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>
                            {isEs ? 'Autor / Creador' : 'Author'}
                          </span>
                          <strong style={{ color: 'var(--text-primary)' }}>{m.author}</strong>
                        </div>
                      )}
                      {m.created_at && (
                        <div>
                          <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>
                            {isEs ? 'Fecha de Creación' : 'Creation Date'}
                          </span>
                          <strong style={{ color: 'var(--text-primary)' }}>{m.created_at.split('T')[0]}</strong>
                        </div>
                      )}
                      <div style={{ gridColumn: '1 / -1', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px', marginTop: '4px' }}>
                        <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', marginBottom: '2px', fontWeight: 600 }}>
                          SHA-256 Hash
                        </span>
                        <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)', wordBreak: 'break-all', fontSize: '12px' }}>
                          {m.sha256}
                        </strong>
                      </div>
                    </>
                  );
                }
                return null;
              })()}

              {/* If it is an email, show Subject & Sender */}
              {result.email_extracted_headers && (
                <>
                  <div>
                    <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>
                      {isEs ? 'Remitente (From)' : 'Sender (From)'}
                    </span>
                    <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{result.email_extracted_headers.From || 'Unknown'}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>
                      {isEs ? 'Asunto (Subject)' : 'Subject'}
                    </span>
                    <strong style={{ color: 'var(--text-primary)' }}>{result.email_extracted_headers.Subject || '(No Subject)'}</strong>
                  </div>
                  {result.email_extracted_headers.SenderIP && (
                    <div>
                      <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>{isEs ? 'IP Remitente' : 'Sender IP'}</span>
                      <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{result.email_extracted_headers.SenderIP}</strong>
                    </div>
                  )}
                  {result.email_extracted_headers.SPF && (
                    <div>
                      <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>SPF</span>
                      <strong style={{ 
                        color: result.email_extracted_headers.SPF === 'PASS' ? 'var(--risk-low)' : 
                               result.email_extracted_headers.SPF === 'FAIL' ? 'var(--risk-high)' : 'var(--risk-medium)' 
                      }}>{result.email_extracted_headers.SPF}</strong>
                    </div>
                  )}
                  {result.email_extracted_headers.DKIM && (
                    <div>
                      <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>DKIM</span>
                      <strong style={{ 
                        color: result.email_extracted_headers.DKIM === 'PASS' ? 'var(--risk-low)' : 
                               result.email_extracted_headers.DKIM === 'FAIL' ? 'var(--risk-high)' : 'var(--risk-medium)' 
                      }}>{result.email_extracted_headers.DKIM}</strong>
                    </div>
                  )}
                  {result.email_extracted_headers.DMARC && (
                    <div>
                      <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>DMARC</span>
                      <strong style={{ 
                        color: result.email_extracted_headers.DMARC === 'PASS' ? 'var(--risk-low)' : 
                               result.email_extracted_headers.DMARC === 'FAIL' ? 'var(--risk-high)' : 'var(--risk-medium)' 
                      }}>{result.email_extracted_headers.DMARC}</strong>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>
    )}

      {/* Local URL Scan Dashboard ("urlscan.io" local simulation) */}
      {result.scan_type === 'url' && (
        <div style={{ marginBottom: '24px' }}>
          <div 
            onClick={() => setShowUrlscanCard(!showUrlscanCard)}
            className="results-panel__section-title"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', userSelect: 'none' }}
          >
            <span>🖥️ {isEs ? 'Análisis de Red y Sitio Activo (Estilo URLscan Local)' : 'Live Site & Network Analysis (Local URLscan Style)'}</span>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 'normal' }}>
              {showUrlscanCard ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
            </span>
          </div>
          {showUrlscanCard && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              
              {/* Row 1: Site Metadata & Technologies */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
                
                {/* Site Host / DNS/ WHOIS info */}
                <div className="card" style={{
                  background: 'rgba(23, 28, 38, 0.4)',
                  border: '1px solid var(--border-primary)',
                  padding: '16px 20px',
                  borderRadius: 'var(--radius-md)',
                  textAlign: 'left'
                }}>
                  <h4 style={{ margin: '0 0 14px 0', fontSize: '13px', color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    🌐 {isEs ? 'Resolución de Dominio & DNS' : 'Domain Resolution & DNS'}
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px' }}>
                    <div>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '11px', display: 'block', textTransform: 'uppercase' }}>
                        {isEs ? 'Dirección IP del Servidor' : 'Server IP Address'}
                      </span>
                      <strong style={{ fontFamily: 'var(--font-mono)', color: result.url_resolved_ip ? 'var(--text-primary)' : 'var(--risk-medium)' }}>
                        {result.url_resolved_ip || (isEs ? 'No se pudo resolver' : 'Could not resolve')}
                      </strong>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '11px', display: 'block', textTransform: 'uppercase' }}>
                        {isEs ? 'Fecha de Creación del Dominio' : 'Domain Creation Date (WHOIS)'}
                      </span>
                      <strong style={{ color: result.url_domain_created ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                        {result.url_domain_created ? new Date(result.url_domain_created).toLocaleDateString() : (isEs ? 'No disponible/Omitido' : 'Not available/Opted out')}
                      </strong>
                    </div>
                  </div>
                </div>

                {/* Profiled Technologies */}
                <div className="card" style={{
                  background: 'rgba(23, 28, 38, 0.4)',
                  border: '1px solid var(--border-primary)',
                  padding: '16px 20px',
                  borderRadius: 'var(--radius-md)',
                  textAlign: 'left'
                }}>
                  <h4 style={{ margin: '0 0 14px 0', fontSize: '13px', color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    🛠️ {isEs ? 'Tecnologías Detectadas' : 'Profiled Technologies'}
                  </h4>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                    {result.url_technologies && result.url_technologies.length > 0 ? (
                      result.url_technologies.map((tech, idx) => (
                        <span key={idx} style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          padding: '3px 8px',
                          borderRadius: '4px',
                          background: 'rgba(6, 182, 212, 0.12)',
                          color: 'var(--cyan)',
                          border: '1px solid rgba(6, 182, 212, 0.25)'
                        }}>
                          {tech}
                        </span>
                      ))
                    ) : (
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {isEs ? 'No se detectaron tecnologías específicas' : 'No target technologies profiled'}
                      </span>
                    )}
                  </div>
                </div>

              </div>

              {/* Redirect Chain */}
              <div className="card" style={{
                background: 'rgba(23, 28, 38, 0.4)',
                border: '1px solid var(--border-primary)',
                padding: '16px 20px',
                borderRadius: 'var(--radius-md)',
                textAlign: 'left'
              }}>
                <h4 style={{ margin: '0 0 14px 0', fontSize: '13px', color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  🔄 {isEs ? 'Ruta de Redirecciones (Redirect Chain)' : 'Redirect Chain Tracking'}
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {result.url_redirect_chain && result.url_redirect_chain.length > 0 ? (
                    result.url_redirect_chain.map((step, idx) => {
                      const isLast = idx === result.url_redirect_chain.length - 1;
                      const statusColor = step.status_code >= 300 && step.status_code < 400 ? 'var(--risk-medium)' : 
                                          step.status_code === 200 ? 'var(--risk-low)' : 'var(--risk-high)';
                      return (
                        <div key={idx} style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '12px',
                          padding: '8px 12px',
                          background: isLast ? 'rgba(6, 182, 212, 0.05)' : 'rgba(255,255,255,0.01)',
                          border: isLast ? '1px solid rgba(6, 182, 212, 0.25)' : '1px solid var(--border-subtle)',
                          borderRadius: '4px',
                          fontSize: '12px',
                          flexWrap: 'wrap'
                        }}>
                          <span style={{
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 'bold',
                            color: statusColor,
                            background: 'rgba(255,255,255,0.03)',
                            padding: '2px 6px',
                            borderRadius: '3px',
                            border: `1px solid ${statusColor}33`
                          }}>
                            {step.status_code || 'CONN_ERR'}
                          </span>
                          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', wordBreak: 'break-all', flex: 1 }}>
                            {step.url}
                          </span>
                          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                            IP: <strong style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>{step.ip}</strong>
                          </span>
                          {step.error && (
                            <span style={{ fontSize: '11px', color: 'var(--risk-high)', display: 'block', width: '100%', marginTop: '4px' }}>
                              ⚠️ Error: {step.error}
                            </span>
                          )}
                        </div>
                      );
                    })
                  ) : (
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {isEs ? 'No hay saltos registrados' : 'No redirect path steps recorded'}
                    </span>
                  )}
                </div>
              </div>

              {/* Wireframe Site Preview (Title, Forms, Text Summary) */}
              <div className="card" style={{
                background: 'rgba(23, 28, 38, 0.4)',
                border: '1px solid var(--border-primary)',
                padding: '16px 20px',
                borderRadius: 'var(--radius-md)',
                textAlign: 'left'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <h3 style={{ margin: 0, fontSize: '14px', color: 'var(--cyan)' }}>
                    🖥️ {isEs ? 'Estructura Interactiva del Sitio (Vista Previa)' : 'Interactive Site Structure (Wireframe Preview)'}
                  </h3>
                </div>
                {result.url_site_preview && (result.url_site_preview.title || result.url_site_preview.forms?.length > 0) ? (
                  <div>
                    {renderZoomControls()}
                    <div style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'top left', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '20px', background: 'rgba(255, 255, 255, 0.02)', position: 'relative', overflow: 'hidden' }}>
                      
                      {/* Window Header */}
                      <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px', marginBottom: '20px' }}>
                        <div style={{ fontSize: '16px', fontWeight: 'bold', color: 'var(--text-primary)', marginBottom: '8px' }}>
                          {result.url_site_preview.title || <span style={{ color: 'var(--text-muted)', fontWeight: 'normal' }}>(None)</span>}
                        </div>
                        {result.url_site_preview.meta_description && (
                          <div style={{ color: 'var(--text-secondary)', fontStyle: 'italic' }}>"{result.url_site_preview.meta_description}"</div>
                        )}
                      </div>
                    <div>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '11px', textTransform: 'uppercase', display: 'block', marginBottom: '8px' }}>
                        {isEs ? 'Formularios e Inputs de Ingreso Detectados' : 'Interactive Form Actions & Input Fields'}
                      </span>
                      {result.url_site_preview.forms && result.url_site_preview.forms.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          {result.url_site_preview.forms.map((form, fIdx) => (
                            <div key={fIdx} style={{
                              background: 'rgba(2, 6, 23, 0.5)',
                              border: '1px solid rgba(6, 182, 212, 0.15)',
                              borderRadius: '6px',
                              padding: '12px 14px'
                            }}>
                              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '8px', fontFamily: 'var(--font-mono)' }}>
                                ACTION: <strong style={{ color: 'var(--cyan)' }}>{form.action || '#'}</strong> · METHOD: <strong style={{ color: 'var(--cyan)' }}>{form.method.toUpperCase()}</strong>
                              </div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                                {form.inputs.map((inp, iIdx) => (
                                  <div key={iIdx} style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '8px',
                                    background: 'rgba(255,255,255,0.02)',
                                    padding: '6px 10px',
                                    borderRadius: '4px',
                                    border: '1px solid var(--border-subtle)'
                                  }}>
                                    <span style={{
                                      fontSize: '9px',
                                      fontWeight: 'bold',
                                      background: inp.type === 'password' ? 'var(--risk-high)' : 'var(--text-muted)',
                                      color: '#000',
                                      padding: '1px 4px',
                                      borderRadius: '3px',
                                      textTransform: 'uppercase'
                                    }}>
                                      {inp.type}
                                    </span>
                                    <span style={{ color: 'var(--text-primary)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                                      name: <strong>{inp.name || '(empty)'}</strong>
                                    </span>
                                    {inp.placeholder && (
                                      <span style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>
                                        (placeholder: "{inp.placeholder}")
                                      </span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ color: 'var(--text-muted)', fontStyle: 'italic', fontSize: '12px' }}>
                          {isEs ? 'No se detectaron formularios de login o inputs de texto interactivos en el HTML final.' : 'No HTML forms or login input fields discovered on the page.'}
                        </div>
                      )}
                    </div>

                    {/* Paragraph Summary Preview */}
                    {result.url_site_preview.text_content && (
                      <div>
                        <span style={{ color: 'var(--text-secondary)', fontSize: '11px', textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
                          {isEs ? 'Resumen de Texto Visible' : 'Visible Text Snippet'}
                        </span>
                        <div style={{
                          background: 'rgba(255,255,255,0.02)',
                          padding: '10px 14px',
                          borderRadius: '4px',
                          border: '1px solid var(--border-subtle)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '11px',
                          lineHeight: '1.4',
                          color: 'var(--text-secondary)'
                        }}>
                          {result.url_site_preview.text_content}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
                ) : (
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {isEs ? 'No hay información de previsualización disponible' : 'No wireframe structure available'}
                  </span>
                )}
              </div>

              {/* Javascript Documents & Script Analysis */}
              <div className="card" style={{
                background: 'rgba(23, 28, 38, 0.4)',
                border: '1px solid var(--border-primary)',
                padding: '16px 20px',
                borderRadius: 'var(--radius-md)',
                textAlign: 'left'
              }}>
                <h4 style={{ margin: '0 0 14px 0', fontSize: '13px', color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  📜 {isEs ? 'Archivos y Código JavaScript del Sitio' : 'JavaScript Script Documents & Analysis'}
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  {result.url_extracted_scripts && result.url_extracted_scripts.length > 0 ? (
                    result.url_extracted_scripts.map((script, idx) => (
                      <div key={idx} style={{
                        background: 'rgba(2, 6, 23, 0.3)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '6px',
                        overflow: 'hidden'
                      }}>
                        <div style={{
                          background: 'rgba(255,255,255,0.02)',
                          padding: '10px 14px',
                          borderBottom: '1px solid var(--border-subtle)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          flexWrap: 'wrap',
                          gap: '10px'
                        }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--cyan)', wordBreak: 'break-all' }}>
                            📄 {script.name}
                          </span>
                          <span style={{
                            fontSize: '10px',
                            fontWeight: 'bold',
                            padding: '2px 6px',
                            borderRadius: '4px',
                            background: script.findings?.length > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                            color: script.findings?.length > 0 ? 'var(--risk-high)' : 'var(--risk-low)',
                            border: `1px solid ${script.findings?.length > 0 ? 'rgba(239, 68, 68, 0.25)' : 'rgba(16, 185, 129, 0.25)'}`
                          }}>
                            {script.findings?.length > 0 ? `${script.findings.length} findings` : 'Clean'}
                          </span>
                        </div>
                        <div style={{ padding: '12px 14px' }}>
                          
                          {/* Script Findings */}
                          {script.findings && script.findings.length > 0 && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px' }}>
                              {script.findings.map((f, fIdx) => (
                                <div key={fIdx} style={{
                                  background: 'rgba(239, 68, 68, 0.05)',
                                  border: '1px solid rgba(239, 68, 68, 0.2)',
                                  padding: '8px 10px',
                                  borderRadius: '4px',
                                  fontSize: '12px'
                                }}>
                                  <strong style={{ color: 'var(--risk-high)' }}>⚠️ {f.title}</strong>
                                  <div style={{ color: 'var(--text-secondary)', marginTop: '2px' }}>{f.detail}</div>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Code preview snippet */}
                          <pre style={{
                            margin: 0,
                            background: '#090d16',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: '4px',
                            padding: '10px',
                            color: '#a78bfa',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            lineHeight: '1.4',
                            whiteSpace: 'pre-wrap',
                            maxHeight: '150px',
                            overflowY: 'auto'
                          }}>
                            {script.content_preview}
                          </pre>
                        </div>
                      </div>
                    ))
                  ) : (
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {isEs ? 'No se detectaron scripts Javascript en la página.' : 'No JavaScript script elements extracted.'}
                    </span>
                  )}
                </div>
              </div>

            </div>
          )}
        </div>
      )}

      {/* 2. Subtle / Compact Scan Result Status Banner */}
      <div 
        style={{
          background: result.risk_score >= 70 
            ? 'rgba(225, 29, 72, 0.08)' 
            : result.risk_score >= 35 
              ? 'rgba(245, 158, 11, 0.08)' 
              : 'rgba(16, 185, 129, 0.08)',
          border: result.risk_score >= 70 
            ? '1px solid rgba(225, 29, 72, 0.4)' 
            : result.risk_score >= 35 
              ? '1px solid rgba(245, 158, 11, 0.4)' 
              : '1px solid rgba(16, 185, 129, 0.4)',

          borderRadius: 'var(--radius-md)',
          padding: '12px 18px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          marginBottom: '20px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', textAlign: 'left' }}>
          <RiskGauge
            score={result.risk_score}
            classification={result.classification}
            compact={true}
          />
          <div>
            <div style={{ 
              fontSize: '15px', 
              fontWeight: '700', 
              color: result.risk_score >= 70 
                ? '#f87171' 
                : result.risk_score >= 35 
                  ? '#fbbf24' 
                  : '#34d399',
            }}>
              {result.risk_score >= 70 
                ? (isEs ? '🚨 Amenaza de Riesgo Detectada' : '🚨 Threat / Risk Detected')
                : result.risk_score >= 35 
                  ? (isEs ? '⚠️ Actividad Sospechosa Detectada' : '⚠️ Suspicious Activity Detected')
                  : (isEs ? '🟢 Archivo Limpio / Sin Actividad Sospechosa' : '🟢 Clean File / No Suspicious Activity')}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginTop: '2px' }}>
              {isEs ? 'Puntaje de Riesgo:' : 'Risk Score:'} <strong style={{ color: 'var(--text-primary)' }}>{result.risk_score}/100</strong>
              {' · '}
              {isEs ? 'Clasificación:' : 'Classification:'} <strong style={{ 
                color: result.risk_score >= 70 
                  ? 'var(--risk-critical)' 
                  : result.risk_score >= 35 
                    ? 'var(--risk-medium)' 
                    : 'var(--risk-low)',
              }}>{result.classification}</strong>
              {' · '}
              {t?.confidence || 'Confidence'}: <strong style={{ color: 'var(--text-primary)' }}>{result.confidence}%</strong>
            </div>
            {/* THREAT TAGS ROW */}
            <div style={{ display: 'flex', gap: '8px', marginTop: '8px', flexWrap: 'wrap' }}>
              {threatTags.map(tag => (
                <span key={tag} style={{
                  padding: '2px 8px',
                  borderRadius: '12px',
                  fontSize: '10px',
                  fontWeight: 'bold',
                  background: 'rgba(255,255,255,0.1)',
                  color: 'var(--cyan)',
                  border: '1px solid rgba(6, 182, 212, 0.3)'
                }}>
                  {tag}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Professional PDF Report Export Button */}
        <div style={{ display: 'flex', gap: '10px' }}>
          <button 
            type="button" 
            onClick={handleDownloadReport} 
            className="btn btn--secondary" 
            style={{
              padding: '6px 14px',
              fontSize: '11px',
              height: '30px',
              borderRadius: '6px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: 'var(--text-primary)',
              background: 'rgba(255, 255, 255, 0.05)',
              cursor: 'pointer'
            }}
          >
            📥 {isEs ? 'Exportar Reporte PDF' : 'Export PDF Report'}
          </button>
          <button 
            type="button" 
            onClick={handleDownloadJson} 
            className="btn btn--secondary" 
            style={{
              padding: '6px 14px',
              fontSize: '11px',
              height: '30px',
              borderRadius: '6px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: 'var(--text-primary)',
              background: 'rgba(255, 255, 255, 0.05)',
              cursor: 'pointer'
            }}
          >
            📋 Export JSON
          </button>
        </div>
      </div>

      {/* Summary */}
      <div 
        onClick={() => setShowSummaryCard(!showSummaryCard)}
        style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          cursor: 'pointer', 
          userSelect: 'none',
          marginBottom: '8px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
          paddingBottom: '4px'
        }}
      >
        <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--cyan)' }}>
          📋 {isEs ? 'Resumen Ejecutivo' : 'Executive Summary'}
        </span>
        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
          {showSummaryCard ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
        </span>
      </div>
      {showSummaryCard && (
        <div className="results-panel__summary" style={{
          textAlign: 'left',
          fontSize: '13px',
          lineHeight: '1.6',
          padding: '12px 16px',
          borderLeft: result.risk_score >= 70 
            ? '3px solid var(--risk-critical)' 
            : result.risk_score >= 35 
              ? '3px solid var(--risk-medium)' 
              : '3px solid var(--risk-low)',
          background: 'rgba(255, 255, 255, 0.01)',
          marginBottom: '24px'
        }}>
          {result.summary}
        </div>
      )}

      {/* File Inventory & Analysis Status (For Documents and Emails) */}
      {analyzedFiles.length > 0 && (
        <div style={{ marginBottom: '32px' }}>
          <div 
            onClick={() => setShowFilesTableCard(!showFilesTableCard)}
            className="results-panel__section-title"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', userSelect: 'none' }}
          >
            <span>📁 {isEs ? 'Detalle de Archivos Detectados y Escaneados' : 'Detected Files & Analysis Status'} ({analyzedFiles.length})</span>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 'normal' }}>
              {showFilesTableCard ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
            </span>
          </div>
          {showFilesTableCard && (
          <div style={{
            background: 'rgba(7, 10, 19, 0.4)',
            border: '1px solid var(--border-primary)',
            borderRadius: 'var(--radius-md)',
            overflow: 'hidden',
            boxShadow: 'var(--shadow-border)'
          }}>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left', minWidth: '600px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-primary)', background: 'rgba(6, 182, 212, 0.06)', color: 'var(--cyan)', fontWeight: 700 }}>
                    <th style={{ padding: '12px 16px' }}>{isEs ? 'Nombre del Archivo' : 'File Name'}</th>
                    <th style={{ padding: '12px 16px' }}>{isEs ? 'Formato' : 'Format'}</th>
                    <th style={{ padding: '12px 16px' }}>{isEs ? 'Estado Forense' : 'Forensic Status'}</th>
                    <th className="table-sticky-col" style={{ padding: '12px 16px', zIndex: 10 }}>{isEs ? 'Resultado del Análisis' : 'Analysis Outcome'}</th>
                  </tr>
                </thead>
                <tbody>
                  {analyzedFiles.map((file, idx) => {
                    const statusInfo = getFindingsForFile(file.name);
                    const filePreview = result.document_file_previews && result.document_file_previews[file.name];
                    const fileChecklist = result.document_file_checks && result.document_file_checks[file.name];
                    
                    let statusBadge = null;
                    if (file.status === 'analyzed') {
                      if (statusInfo.total === 0) {
                        statusBadge = (
                          <span style={{ color: 'var(--risk-low)', background: 'rgba(16, 185, 129, 0.1)', padding: '3px 10px', borderRadius: '4px', border: '1px solid rgba(16, 185, 129, 0.2)', fontSize: '11px', fontWeight: 700 }}>
                            🟢 {isEs ? 'Limpio' : 'Clean'}
                          </span>
                        );
                      } else if (statusInfo.critical > 0) {
                        statusBadge = (
                          <span 
                            style={{ color: 'var(--risk-high)', background: 'rgba(244, 63, 94, 0.1)', padding: '3px 10px', borderRadius: '4px', border: '1px solid rgba(244, 63, 94, 0.2)', fontSize: '11px', fontWeight: 700, cursor: 'pointer' }}
                            onClick={() => {
                              setExpandedPreview(expandedPreview === file.name ? null : file.name);
                              setExpandedChecks(null);
                              setExpandedMetadata(null);
                              setExpandedDeobfuscated(null);
                            }}
                            title={isEs ? 'Clic para ver la evidencia/código malicioso' : 'Click to view the malicious string/code evidence'}
                          >
                            🔴 {isEs ? 'MALICIOSO' : 'MALICIOUS'} ({statusInfo.total})
                          </span>
                        );
                      } else {
                        statusBadge = (
                          <span 
                            style={{ color: 'var(--risk-medium)', background: 'rgba(245, 158, 11, 0.1)', padding: '3px 10px', borderRadius: '4px', border: '1px solid rgba(245, 158, 11, 0.2)', fontSize: '11px', fontWeight: 700, cursor: 'pointer' }}
                            onClick={() => {
                              setExpandedPreview(expandedPreview === file.name ? null : file.name);
                              setExpandedChecks(null);
                              setExpandedMetadata(null);
                              setExpandedDeobfuscated(null);
                            }}
                            title={isEs ? 'Clic para ver la evidencia/código' : 'Click to view the evidence/code'}
                          >
                            ⚠️ {isEs ? 'SOSPECHOSO' : 'SUSPICIOUS'} ({statusInfo.total})
                          </span>
                        );
                      }
                    } else if (file.status === 'skipped') {
                      statusBadge = (
                        <span style={{ color: 'var(--text-secondary)', background: 'rgba(255, 255, 255, 0.05)', padding: '3px 10px', borderRadius: '4px', border: '1px solid rgba(255, 255, 255, 0.1)', fontSize: '11px' }}>
                          ⚪ {isEs ? 'Omitido' : 'Omitted'}
                        </span>
                      );
                    } else {
                      statusBadge = (
                        <span style={{ color: 'var(--risk-high)', background: 'rgba(244, 63, 94, 0.1)', padding: '3px 10px', borderRadius: '4px', border: '1px solid rgba(244, 63, 94, 0.2)', fontSize: '11px' }}>
                          ❌ {isEs ? 'Error' : 'Error'}
                        </span>
                      );
                    }
                    
                    const isPreviewOpen = expandedPreview === file.name;
                    const isChecksOpen = expandedChecks === file.name;
                    const isMetadataOpen = expandedMetadata === file.name;
                    const isDeobfOpen = expandedDeobfuscated === file.name;
                    const isStringsOpen = expandedStrings === file.name;
                    const fileMetadata = result.document_file_metadata && result.document_file_metadata[file.name];
                    const fileContext = result.document_file_contexts && result.document_file_contexts[file.name];
                    const fileDeobf = result.document_file_deobfuscated && result.document_file_deobfuscated[file.name];
                    const fileStrings = result.document_file_strings && result.document_file_strings[file.name];

                    return (
                      <React.Fragment key={idx}>
                        <tr style={{ borderBottom: (isPreviewOpen || isChecksOpen || isMetadataOpen || isDeobfOpen || isStringsOpen) ? 'none' : '1px solid var(--border-subtle)', transition: 'background 0.2s' }}
                            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)'}
                            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                          <td style={{ padding: '14px 16px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                              <span style={{ wordBreak: 'break-all' }}>📄 {file.name}</span>
                              {fileDeobf && fileDeobf.length > 0 && (
                                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '2px' }}>
                                  {Array.from(new Set(fileDeobf.map(item => {
                                    const t = item.type || "";
                                    if (t.includes("Base64")) return "Base64";
                                    if (t.includes("Hex")) return "Hex";
                                    if (t.includes("XOR")) {
                                      const keyMatch = t.match(/Key:\s*(0x[0-9a-fA-F]+)/);
                                      return keyMatch ? `XOR (${keyMatch[1]})` : "XOR";
                                    }
                                    if (t.includes("fromCharCode")) return "fromCharCode";
                                    if (t.includes("Integer Array")) return "Int Array";
                                    if (t.includes("URL-Encoded")) return "URL Enc";
                                    if (t.includes("Unicode")) return "Unicode";
                                    if (t.includes("Octal")) return "Octal";
                                    return t.replace(" Decoded", "").replace(" Detected", "");
                                  }))).map((tName, tagIdx) => (
                                    <span key={tagIdx} style={{
                                      padding: '1px 6px',
                                      background: 'rgba(16, 185, 129, 0.15)',
                                      color: '#34d399',
                                      borderRadius: '3px',
                                      border: '1px solid rgba(16, 185, 129, 0.3)',
                                      fontSize: '9px',
                                      fontWeight: 'bold',
                                      textTransform: 'uppercase',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '2px',
                                      letterSpacing: '0.3px'
                                    }}>
                                      🔒 {tName}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </td>
                          <td style={{ padding: '14px 16px' }}>
                            <span style={{
                              padding: '2px 6px',
                              background: 'rgba(6, 182, 212, 0.1)',
                              color: 'var(--cyan)',
                              borderRadius: '4px',
                              border: '1px solid rgba(6, 182, 212, 0.2)',
                              fontSize: '11px',
                              textTransform: 'uppercase',
                              fontWeight: 700
                            }}>
                              {file.type.replace('.', '')}
                            </span>
                          </td>
                          <td style={{ padding: '14px 16px', color: 'var(--text-secondary)', fontSize: '12px' }}>
                            <div>{file.details}</div>
                            {fileContext && (
                              <div style={{
                                marginTop: '6px',
                                color: '#cbd5e1',
                                fontStyle: 'italic',
                                fontSize: '11px',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                background: 'rgba(99, 102, 241, 0.15)',
                                border: '1px solid rgba(99, 102, 241, 0.3)',
                                padding: '2px 8px',
                                borderRadius: '4px',
                                textShadow: '0 0 5px rgba(99, 102, 241, 0.2)'
                              }}>
                                🧠 {isEs ? 'Contexto' : 'Context'}: {fileContext}
                              </div>
                            )}
                          </td>
                          <td className="table-sticky-col" style={{ padding: '14px 16px' }}>
                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                              {statusBadge}
                              
                              {fileChecklist && fileChecklist.length > 0 && (
                                <button
                                  type="button"
                                  className="btn btn--secondary"
                                  onClick={() => {
                                    setExpandedChecks(isChecksOpen ? null : file.name);
                                    setExpandedPreview(null);
                                    setExpandedMetadata(null);
                                    setExpandedDeobfuscated(null);
                                  }}
                                  style={{ padding: '4px 10px', fontSize: '11px', borderRadius: '4px', textTransform: 'none', height: '26px', whiteSpace: 'nowrap' }}
                                >
                                  🛡️ {isChecksOpen ? (isEs ? 'Ocultar' : 'Hide') : (isEs ? 'Chequeos de Seguridad' : 'Security Checks')}
                                </button>
                              )}

                              {filePreview && (
                                <button
                                  type="button"
                                  className="btn btn--primary"
                                  onClick={() => {
                                    setExpandedPreview(isPreviewOpen ? null : file.name);
                                    setExpandedChecks(null);
                                    setExpandedMetadata(null);
                                    setExpandedDeobfuscated(null);
                                  }}
                                  style={{ padding: '4px 10px', fontSize: '11px', borderRadius: '4px', textTransform: 'none', height: '26px', whiteSpace: 'nowrap' }}
                                >
                                  🔍 {isPreviewOpen ? (isEs ? 'Ocultar' : 'Hide') : (isEs ? 'Vista de Código' : 'Code preview')}
                                </button>
                              )}

                              {fileMetadata && (
                                <button
                                  type="button"
                                  className="btn btn--secondary"
                                  onClick={() => {
                                    setExpandedMetadata(isMetadataOpen ? null : file.name);
                                    setExpandedPreview(null);
                                    setExpandedChecks(null);
                                    setExpandedDeobfuscated(null);
                                  }}
                                  style={{
                                    padding: '4px 10px',
                                    fontSize: '11px',
                                    borderRadius: '4px',
                                    textTransform: 'none',
                                    height: '26px',
                                    whiteSpace: 'nowrap',
                                    border: '1px solid rgba(139, 92, 246, 0.3)',
                                    color: '#c084fc',
                                    background: isMetadataOpen ? 'rgba(139, 92, 246, 0.2)' : 'transparent'
                                  }}
                                >
                                  📊 {isMetadataOpen ? (isEs ? 'Ocultar' : 'Hide') : (isEs ? 'Metadatos de Archivo' : 'File Metadata')}
                                </button>
                              )}

                              {fileDeobf && fileDeobf.length > 0 && (
                                <button
                                  type="button"
                                  className="btn"
                                  onClick={() => {
                                    setExpandedDeobfuscated(isDeobfOpen ? null : file.name);
                                    setExpandedPreview(null);
                                    setExpandedChecks(null);
                                    setExpandedMetadata(null);
                                  }}
                                  style={{
                                    padding: '4px 10px',
                                    fontSize: '11px',
                                    borderRadius: '4px',
                                    textTransform: 'none',
                                    height: '26px',
                                    whiteSpace: 'nowrap',
                                    background: isDeobfOpen ? 'rgba(16, 185, 129, 0.2)' : 'rgba(16, 185, 129, 0.1)',
                                    border: '1px solid rgba(16, 185, 129, 0.3)',
                                    color: '#34d399',
                                    fontWeight: 700
                                  }}
                                >
                                  🔓 {isDeobfOpen ? (isEs ? 'Ocultar' : 'Hide') : (isEs ? 'Código Desofuscado' : 'Deobfuscated code')} ({fileDeobf.length})
                                </button>
                              )}

                              {fileStrings && (
                                <button
                                  type="button"
                                  className="btn"
                                  onClick={() => {
                                    setExpandedStrings(isStringsOpen ? null : file.name);
                                    setExpandedPreview(null);
                                    setExpandedChecks(null);
                                    setExpandedMetadata(null);
                                    setExpandedDeobfuscated(null);
                                  }}
                                  style={{
                                    padding: '4px 10px',
                                    fontSize: '11px',
                                    borderRadius: '4px',
                                    textTransform: 'none',
                                    height: '26px',
                                    whiteSpace: 'nowrap',
                                    background: isStringsOpen ? 'rgba(234, 179, 8, 0.2)' : 'rgba(234, 179, 8, 0.1)',
                                    border: '1px solid rgba(234, 179, 8, 0.3)',
                                    color: '#facc15',
                                    fontWeight: 700
                                  }}
                                >
                                  📝 {isStringsOpen ? (isEs ? 'Ocultar' : 'Hide') : (isEs ? 'Strings' : 'Strings')}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>

                        {/* Conditionally render metadata drawer */}
                        {isMetadataOpen && fileMetadata && (
                          <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(2, 6, 23, 0.4)' }}>
                            <td colSpan="4" style={{ padding: '16px 24px' }}>
                              <div style={{
                                background: 'rgba(15, 23, 42, 0.65)',
                                backdropFilter: 'blur(12px)',
                                WebkitBackdropFilter: 'blur(12px)',
                                padding: '20px 24px',
                                borderRadius: 'var(--radius-md)',
                                border: '1px solid rgba(139, 92, 246, 0.3)',
                                boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.5), inset 0 0 20px rgba(139, 92, 246, 0.05)',
                                textAlign: 'left',
                                maxWidth: '100%',
                                overflow: 'hidden'
                              }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid rgba(139, 92, 246, 0.2)', paddingBottom: '10px' }}>
                                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#c084fc', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    📊 {isEs ? 'METADATOS FORENSES & HASHES' : 'FORENSIC METADATA & HASHES'} : {file.name}
                                  </span>
                                  <span style={{ fontSize: '10px', color: '#a78bfa', background: 'rgba(139, 92, 246, 0.1)', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(139, 92, 246, 0.2)' }}>
                                    {isEs ? 'Local e Inalterable' : 'Local & Untampered'}
                                  </span>
                                </div>
                                
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', fontSize: '12px' }}>
                                  
                                  {/* Column 1: Core details */}
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                    <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                      <div style={{ color: 'var(--text-muted)', fontSize: '10px', textTransform: 'uppercase', marginBottom: '4px' }}>
                                        {isEs ? 'Autor / Creador' : 'Author / Creator'}
                                      </div>
                                      <div style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                                        {fileMetadata.author || 'Unknown'}
                                      </div>
                                    </div>
                                    
                                    <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                      <div style={{ color: 'var(--text-muted)', fontSize: '10px', textTransform: 'uppercase', marginBottom: '4px' }}>
                                        {isEs ? 'Fecha de Creación / Análisis' : 'Created / Analyzed Date'}
                                      </div>
                                      <div style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                                        {fileMetadata.created_at || 'N/A'}
                                      </div>
                                    </div>

                                    <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                      <div style={{ color: 'var(--text-muted)', fontSize: '10px', textTransform: 'uppercase', marginBottom: '4px' }}>
                                        {isEs ? 'Tamaño del Archivo' : 'File Size'}
                                      </div>
                                      <div style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                                        {fileMetadata.file_size_bytes ? `${fileMetadata.file_size_bytes.toLocaleString()} bytes` : 'N/A'}
                                      </div>
                                    </div>
                                  </div>

                                  {/* Column 2: Cryptographic Hashes */}
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                    <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                      <div style={{ color: 'var(--text-muted)', fontSize: '10px', textTransform: 'uppercase', marginBottom: '4px', display: 'flex', justifyContent: 'space-between' }}>
                                        <span>MD5</span>
                                        <span style={{ color: 'var(--cyan)', cursor: 'pointer' }} onClick={() => navigator.clipboard.writeText(fileMetadata.md5)} title="Copiar Hash">📋</span>
                                      </div>
                                      <div style={{ color: 'var(--cyan)', fontWeight: 600, fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                                        {fileMetadata.md5 || 'N/A'}
                                      </div>
                                    </div>

                                    <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                      <div style={{ color: 'var(--text-muted)', fontSize: '10px', textTransform: 'uppercase', marginBottom: '4px', display: 'flex', justifyContent: 'space-between' }}>
                                        <span>SHA-256</span>
                                        <span style={{ color: 'var(--cyan)', cursor: 'pointer' }} onClick={() => navigator.clipboard.writeText(fileMetadata.sha256)} title="Copiar Hash">📋</span>
                                      </div>
                                      <div style={{ color: 'var(--cyan)', fontWeight: 600, fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                                        {fileMetadata.sha256 || 'N/A'}
                                      </div>
                                    </div>
                                  </div>

                                </div>

                                {/* Full-width SHA-512 */}
                                <div style={{ marginTop: '16px', background: 'rgba(255, 255, 255, 0.02)', padding: '12px 16px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                  <div style={{ color: 'var(--text-muted)', fontSize: '10px', textTransform: 'uppercase', marginBottom: '6px', display: 'flex', justifyContent: 'space-between' }}>
                                    <span>SHA-512</span>
                                    <span style={{ color: 'var(--cyan)', cursor: 'pointer' }} onClick={() => navigator.clipboard.writeText(fileMetadata.sha512)} title="Copiar Hash">📋</span>
                                  </div>
                                  <div style={{ color: '#a78bfa', fontWeight: 600, fontFamily: 'var(--font-mono)', wordBreak: 'break-all', fontSize: '11px', lineHeight: '1.4' }}>
                                    {fileMetadata.sha512 || 'N/A'}
                                  </div>
                                </div>

                              </div>
                            </td>
                          </tr>
                        )}

                        {/* Conditionally render code preview drawer with Code vs Hex views */}
                        {isPreviewOpen && filePreview && (
                          <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(2, 6, 23, 0.4)' }}>
                            <td colSpan="4" style={{ padding: '16px 24px' }}>
                              <div style={{
                                background: '#020617',
                                padding: '16px 20px',
                                borderRadius: 'var(--radius-sm)',
                                border: '1px solid rgba(6, 182, 212, 0.25)',
                                boxShadow: 'inset 0 0 15px rgba(0, 0, 0, 0.6)',
                                maxWidth: '100%',
                                overflow: 'hidden'
                              }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.03)', paddingBottom: '8px' }}>
                                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                    <button
                                      type="button"
                                      onClick={() => setPreviewTab(prev => ({ ...prev, [file.name]: 'code' }))}
                                      style={{
                                        background: (previewTab[file.name] || 'code') === 'code' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                                        border: `1px solid ${(previewTab[file.name] || 'code') === 'code' ? 'var(--cyan)' : 'transparent'}`,
                                        color: (previewTab[file.name] || 'code') === 'code' ? 'var(--text-primary)' : 'var(--text-secondary)',
                                        padding: '4px 12px',
                                        borderRadius: '4px',
                                        fontSize: '11px',
                                        fontWeight: 700,
                                        cursor: 'pointer',
                                        fontFamily: 'var(--font-mono)'
                                      }}
                                    >
                                      📄 {isEs ? 'Código / Texto' : 'Code / Text'}
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() => setPreviewTab(prev => ({ ...prev, [file.name]: 'hex' }))}
                                      style={{
                                        background: (previewTab[file.name] || 'code') === 'hex' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                                        border: `1px solid ${(previewTab[file.name] || 'code') === 'hex' ? 'var(--cyan)' : 'transparent'}`,
                                        color: (previewTab[file.name] || 'code') === 'hex' ? 'var(--text-primary)' : 'var(--text-secondary)',
                                        padding: '4px 12px',
                                        borderRadius: '4px',
                                        fontSize: '11px',
                                        fontWeight: 700,
                                        cursor: 'pointer',
                                        fontFamily: 'var(--font-mono)'
                                      }}
                                    >
                                      🔢 {isEs ? 'Visor Hexadecimal' : 'Hex Viewer'}
                                    </button>
                                  </div>
                                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                                    {isEs ? 'Análisis Forense Local' : 'Local Forensic Triage'}
                                  </span>
                                  {renderZoomControls()}
                                </div>

                                {(() => {
                                  const currentTab = previewTab[file.name] || 'code';
                                  
                                  if (currentTab === 'hex') {
                                    // Generate classical 16-byte hex dump
                                    const generateHexDump = (str) => {
                                      const lines = [];
                                      const bytes = Array.from(str).map(c => c.charCodeAt(0) & 0xFF);
                                      for (let i = 0; i < bytes.length; i += 16) {
                                        const chunk = bytes.slice(i, i + 16);
                                        const offset = i.toString(16).padStart(8, '0').toUpperCase();
                                        const hex = chunk.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
                                        const paddedHex = hex + ' '.repeat((16 - chunk.length) * 3);
                                        const ascii = chunk.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
                                        lines.push(`${offset}  ${paddedHex}  |${ascii}|`);
                                      }
                                      return lines.join('\n');
                                    };

                                    const hexDump = generateHexDump(filePreview);
                                    const hexLines = hexDump.split('\n');
                                    const needsTruncation = hexLines.length > 25;
                                    const isExpanded = fullCodeExpanded[file.name + '_hex'] || false;
                                    
                                    let displayedHex = hexDump;
                                    if (needsTruncation && !isExpanded) {
                                      displayedHex = hexLines.slice(0, 25).join('\n') + '\n\n... [HEX COLAPSADO - HAZ CLIC EN EL BOTÓN ABAJO PARA VER TODO]';
                                    }

                                    return (
                                      <div>
                                        <pre style={{
                                          margin: 0,
                                          padding: '12px 16px',
                                          background: '#090d16',
                                          color: '#38bdf8',
                                          fontFamily: 'var(--font-mono)',
                                          fontSize: `${11 * zoomLevel}px`,
                                          lineHeight: '1.5',
                                          maxHeight: isExpanded ? '600px' : '400px',
                                          overflow: 'auto',
                                          border: '1px solid rgba(255, 255, 255, 0.03)',
                                          borderRadius: '4px',
                                          whiteSpace: 'pre',
                                          textAlign: 'left'
                                        }}>
                                          {displayedHex}
                                        </pre>
                                        {needsTruncation && (
                                          <div style={{ marginTop: '10px', display: 'flex', justifyContent: 'flex-start' }}>
                                            <button
                                              type="button"
                                              className="btn"
                                              onClick={() => {
                                                setFullCodeExpanded(prev => ({
                                                  ...prev,
                                                  [file.name + '_hex']: !isExpanded
                                                }));
                                              }}
                                              style={{
                                                padding: '6px 12px',
                                                fontSize: '11px',
                                                background: isExpanded ? 'rgba(239, 68, 68, 0.1)' : 'rgba(6, 182, 212, 0.1)',
                                                border: `1px solid ${isExpanded ? 'rgba(239, 68, 68, 0.3)' : 'rgba(6, 182, 212, 0.3)'}`,
                                                color: isExpanded ? 'var(--risk-high)' : 'var(--cyan)',
                                                borderRadius: '4px',
                                                cursor: 'pointer',
                                                fontWeight: 700,
                                                height: '28px',
                                                textTransform: 'none'
                                              }}
                                            >
                                              {isExpanded 
                                                ? `➖ ${isEs ? 'Colapsar hex' : 'Collapse hex'}` 
                                                : `➕ ${isEs ? 'Ver hex completo' : 'Show full hex'}`}
                                            </button>
                                          </div>
                                        )}
                                      </div>
                                    );
                                  }

                                  // Standard Code Text View
                                  const codeLines = filePreview.split('\n');
                                  const needsTruncation = codeLines.length > 25 || filePreview.length > 1500;
                                  const isExpanded = fullCodeExpanded[file.name] || false;
                                  
                                  let displayedText = filePreview;
                                  if (needsTruncation && !isExpanded) {
                                    displayedText = codeLines.slice(0, 25).join('\n') + '\n\n... [CONTENIDO COLAPSADO - HAZ CLIC EN EL BOTÓN "+" ABAJO PARA VER TODO]';
                                  }
                                  
                                  return (
                                    <div>
                                      <pre style={{
                                        margin: 0,
                                        padding: '12px 16px',
                                        background: '#090d16',
                                        color: '#f8fafc',
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: `${12 * zoomLevel}px`,
                                        lineHeight: '1.6',
                                        maxHeight: isExpanded ? '600px' : '400px',
                                        overflow: 'auto',
                                        border: '1px solid rgba(255, 255, 255, 0.03)',
                                        borderRadius: '4px',
                                        whiteSpace: 'pre-wrap',
                                        wordBreak: 'break-all',
                                        textAlign: 'left'
                                      }}>
                                        {displayedText}
                                      </pre>
                                      {needsTruncation && (
                                        <div style={{ marginTop: '10px', display: 'flex', justifyContent: 'flex-start' }}>
                                          <button
                                            type="button"
                                            className="btn"
                                            onClick={() => {
                                              setFullCodeExpanded(prev => ({
                                                ...prev,
                                                [file.name]: !isExpanded
                                              }));
                                            }}
                                            style={{
                                              padding: '6px 12px',
                                              fontSize: '11px',
                                              background: isExpanded ? 'rgba(239, 68, 68, 0.1)' : 'rgba(6, 182, 212, 0.1)',
                                              border: `1px solid ${isExpanded ? 'rgba(239, 68, 68, 0.3)' : 'rgba(6, 182, 212, 0.3)'}`,
                                              color: isExpanded ? 'var(--risk-high)' : 'var(--cyan)',
                                              borderRadius: '4px',
                                              cursor: 'pointer',
                                              fontWeight: 700,
                                              transition: 'all 0.2s',
                                              height: '28px',
                                              textTransform: 'none'
                                            }}
                                            onMouseEnter={e => e.currentTarget.style.background = isExpanded ? 'rgba(239, 68, 68, 0.2)' : 'rgba(6, 182, 212, 0.2)'}
                                            onMouseLeave={e => e.currentTarget.style.background = isExpanded ? 'rgba(239, 68, 68, 0.1)' : 'rgba(6, 182, 212, 0.1)'}
                                          >
                                            {isExpanded 
                                              ? `➖ ${isEs ? 'Colapsar código' : 'Collapse code'}` 
                                              : `➕ ${isEs ? 'Ver todo el código completo' : 'Show full code complete'}`}
                                          </button>
                                        </div>
                                      )}
                                    </div>
                                  );
                                })()}
                              </div>
                            </td>
                          </tr>
                        )}

                        {/* Conditionally render deobfuscator drawer */}
                        {isDeobfOpen && fileDeobf && (
                          <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(2, 6, 23, 0.4)' }}>
                            <td colSpan="4" style={{ padding: '16px 24px' }}>
                              <div style={{
                                        background: 'rgba(9, 13, 22, 0.7)',
                                        backdropFilter: 'blur(12px)',
                                        WebkitBackdropFilter: 'blur(12px)',
                                        padding: '20px 24px',
                                        borderRadius: 'var(--radius-md)',
                                        border: '1px solid rgba(16, 185, 129, 0.3)',
                                        boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.5), inset 0 0 20px rgba(16, 185, 129, 0.05)',
                                        textAlign: 'left',
                                        maxWidth: '100%',
                                        overflow: 'hidden'
                                      }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid rgba(16, 185, 129, 0.2)', paddingBottom: '10px' }}>
                                  <span style={{ fontSize: '13px', fontWeight: 700, color: '#34d399', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    🔓 {isEs ? 'PAYLOADS AUTOMÁTICAMENTE DEOBFUSCADOS' : 'AUTOMATICALLY DEOBFUSCATED PAYLOADS'} : {file.name}
                                  </span>
                                  <span style={{ fontSize: '10px', color: '#34d399', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                                    {isEs ? 'Análisis Recursivo' : 'Recursive Triage'}
                                  </span>
                                </div>

                                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                                  {fileDeobf.map((item, idx) => (
                                    <div key={idx} style={{
                                      background: '#020617',
                                      borderRadius: '6px',
                                      border: '1px solid rgba(255, 255, 255, 0.03)',
                                      overflow: 'hidden'
                                    }}>
                                      <div style={{
                                        background: 'rgba(16, 185, 129, 0.08)',
                                        padding: '8px 14px',
                                        fontSize: '11px',
                                        fontWeight: 700,
                                        color: '#34d399',
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        borderBottom: '1px solid rgba(255, 255, 255, 0.03)'
                                      }}>
                                        <span>🛠️ {isEs ? 'Método Detectado' : 'Method Detected'}: {item.type || item.method || 'Unknown Method'}</span>
                                        <span style={{ color: 'var(--text-muted)' }}>Segment #{idx + 1}</span>
                                      </div>
                                      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '12px', padding: '14px' }}>
                                        <div>
                                          <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
                                            {isEs ? 'Fragmento Obscuro Original' : 'Original Obfuscated Segment'}
                                          </div>
                                          <pre style={{
                                            margin: 0,
                                            padding: '8px 12px',
                                            background: '#090d16',
                                            color: 'var(--text-secondary)',
                                            borderRadius: '4px',
                                            fontSize: '11px',
                                            fontFamily: 'var(--font-mono)',
                                            whiteSpace: 'pre-wrap',
                                            wordBreak: 'break-all',
                                            maxHeight: '200px',
                                            overflow: 'auto'
                                          }}>
                                            {item.obfuscated}
                                          </pre>
                                        </div>
                                        <div>
                                          <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px', display: 'flex', justifyContent: 'space-between' }}>
                                            <span>🔓 {isEs ? 'Carga Útil Decodificada' : 'Decoded Payload String'}</span>
                                            <span style={{ color: 'var(--cyan)', cursor: 'pointer' }} onClick={() => navigator.clipboard.writeText(item.decoded)} title="Copiar Payload">📋</span>
                                          </div>
                                          <pre style={{
                                            margin: 0,
                                            padding: '10px 14px',
                                            background: 'rgba(6, 182, 212, 0.04)',
                                            color: '#f8fafc',
                                            border: '1px solid rgba(6, 182, 212, 0.15)',
                                            borderRadius: '4px',
                                            fontSize: '12px',
                                            lineHeight: '1.5',
                                            fontFamily: 'var(--font-mono)',
                                            whiteSpace: 'pre-wrap',
                                            wordBreak: 'break-all',
                                            maxHeight: '300px',
                                            overflow: 'auto',
                                            textAlign: 'left'
                                          }}>
                                            {item.decoded}
                                          </pre>
                                        </div>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}

                        {/* Conditionally render checklists drawer */}
                        {isChecksOpen && fileChecklist && (
                          <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(2, 6, 23, 0.4)' }}>
                            <td colSpan="4" style={{ padding: '16px 24px' }}>
                              <div style={{
                                background: '#020617',
                                padding: '16px 20px',
                                borderRadius: 'var(--radius-sm)',
                                border: '1px solid rgba(217, 70, 239, 0.25)',
                                boxShadow: 'inset 0 0 15px rgba(0, 0, 0, 0.6)',
                                maxWidth: '100%',
                                overflow: 'hidden'
                              }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                                  <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--violet)', fontFamily: 'var(--font-mono)' }}>
                                    🛡️ {isEs ? 'AUDITORÍA DE INDICADORES Y FIRMAS' : 'INDICATOR & SIGNATURE SECURITY AUDIT'} : {file.name}
                                  </span>
                                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                                    {isEs ? 'Chequeo Forense Estático' : 'Forensic Security Checks'}
                                  </span>
                                </div>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px' }}>
                                  {fileChecklist.map((check, cIdx) => (
                                    <div key={cIdx} style={{
                                      display: 'flex',
                                      alignItems: 'center',
                                      justifyContent: 'space-between',
                                      padding: '8px 14px',
                                      background: check.found ? 'rgba(244, 63, 94, 0.05)' : 'rgba(16, 185, 129, 0.03)',
                                      borderRadius: '4px',
                                      borderLeft: `3px solid ${check.found ? 'var(--risk-high)' : 'var(--risk-low)'}`,
                                      border: '1px solid rgba(255, 255, 255, 0.02)',
                                      borderLeftWidth: '3px'
                                    }}>
                                      <span style={{ fontSize: '12px', color: check.found ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                                        {check.found ? '❌' : '🟢'} {check.name}
                                      </span>
                                      <span style={{
                                        fontSize: '10px',
                                        fontWeight: 700,
                                        padding: '2px 8px',
                                        borderRadius: '4px',
                                        background: check.found ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.1)',
                                        color: check.found ? 'var(--risk-high)' : 'var(--risk-low)',
                                        border: `1px solid ${check.found ? 'rgba(244, 63, 94, 0.25)' : 'rgba(16, 185, 129, 0.2)'}`
                                      }}>
                                        {check.found 
                                          ? (isEs ? 'DETECTADO / RIESGO' : 'DETECTED / THREAT') 
                                          : (isEs ? 'SEGURO / NO ENCONTRADO' : 'CLEAN / NOT FOUND')}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                        
                        {/* Strings Drawer */}
                        {isStringsOpen && fileStrings && (
                          <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(2, 6, 23, 0.4)' }}>
                            <td colSpan="4" style={{ padding: '16px 24px' }}>
                              <div style={{
                                background: '#070a13',
                                border: '1px solid var(--border-subtle)',
                                borderRadius: '8px',
                                padding: '16px',
                                maxHeight: expandedStrings[file.name] ? 'none' : '400px',
                                overflowY: 'auto',
                                position: 'relative'
                              }}>
                                <div style={{ fontSize: '12px', fontWeight: 'bold', color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', justifyContent: 'space-between' }}>
                                  <span>{isEs ? 'Cadenas de texto extraídas (Strings)' : 'Extracted Strings'}</span>
                                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                    <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>{fileStrings.split('\n').length} lines</span>
                                  </div>
                                </div>
                                <pre style={{
                                  margin: 0,
                                  fontSize: '11px',
                                  fontFamily: 'var(--font-mono)',
                                  color: 'var(--text-secondary)',
                                  whiteSpace: 'pre-wrap',
                                  wordBreak: 'break-all'
                                }}>
                                  {fileStrings}
                                </pre>
                              </div>
                            </td>
                          </tr>
                        )}

                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
          )}
        </div>
      )}

      {/* Password cracked info */}
      {result.document_password_found !== null && result.document_password_found !== undefined && (
        <div style={{
          padding: '12px 16px',
          background: 'rgba(139, 92, 246, 0.1)',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid rgba(139, 92, 246, 0.3)',
          marginBottom: '16px',
          fontFamily: 'var(--font-mono)',
          fontSize: '13px',
        }}>
          🔓 {t?.password_cracked || 'Password Found'}: <strong>{result.document_password_found || '(empty)'}</strong>
          {result.document_password_attempts && (
            <span style={{ color: 'var(--text-muted)', marginLeft: '12px' }}>
              ({result.document_password_attempts} {t?.attempts || 'attempts'})
            </span>
          )}
        </div>
      )}

      
      </div>

      <div style={{ display: activeTab === "intel" ? "block" : "none" }}>

      {/* Third-Party VirusTotal Document Hash Check Showcase */}
      {result.third_party_results?.virustotal && (
        <div style={{ marginBottom: '32px' }}>
          <div 
            onClick={() => setShowVtCard(!showVtCard)}
            className="results-panel__section-title"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', userSelect: 'none' }}
          >
            <span>🌐 VirusTotal Hash Reputation Check</span>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 'normal' }}>
              {showVtCard ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
            </span>
          </div>
          {showVtCard && (
            <div className="card" style={{
              border: result.third_party_results.virustotal.malicious_count > 0 ? '1px solid var(--risk-high)' : '1px solid var(--risk-low)',
              background: 'rgba(7, 10, 19, 0.6)',
              padding: '20px',
              borderRadius: 'var(--radius-md)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
                <div>
                  <div style={{ fontSize: '16px', fontWeight: '700', color: result.third_party_results.virustotal.malicious_count > 0 ? 'var(--risk-high)' : 'var(--risk-low)' }}>
                    {result.third_party_results.virustotal.malicious_count > 0 
                      ? `⚠️ MALICIOUS HASH DETECTED (${result.third_party_results.virustotal.score})`
                      : `🟢 HASH CLEAN OR UNKNOWN ON VT (${result.third_party_results.virustotal.score || '0 detections'})`}
                  </div>
                  {result.third_party_results.virustotal.threat_label && result.third_party_results.virustotal.threat_label !== 'Unknown' && (
                    <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                      Suggested Threat Label: <strong style={{ color: 'var(--text-primary)' }}>{result.third_party_results.virustotal.threat_label}</strong>
                    </div>
                  )}
                  {result.third_party_results.virustotal.message && (
                    <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                      {result.third_party_results.virustotal.message}
                    </div>
                  )}
                </div>
                {result.third_party_results.virustotal.permalink && (
                  <a 
                    href={result.third_party_results.virustotal.permalink} 
                    target="_blank" 
                    rel="noopener noreferrer" 
                    className="btn btn--primary"
                    style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '8px', fontSize: '12px', height: '32px' }}
                  >
                    🔍 View VT Report
                  </a>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Extracted IoCs Reputation Placeholder */}
      {((result.email_extracted_ips && result.email_extracted_ips.length > 0) || (result.email_extracted_urls && result.email_extracted_urls.length > 0)) && (
        <div style={{ marginBottom: '32px' }}>
          <div className="results-panel__section-title">
            <span>🔌 IoC Reputation Intel (URLs & IPs)</span>
          </div>
          <div className="card" style={{
            background: 'rgba(7, 10, 19, 0.6)',
            padding: '20px',
            borderRadius: 'var(--radius-md)',
            border: '1px dashed rgba(96, 165, 250, 0.3)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '16px' }}>
              <div style={{ fontSize: '32px' }}>🔑</div>
              <div>
                <h4 style={{ color: 'var(--text-primary)', margin: 0, fontSize: '15px' }}>API Key Required</h4>
                <p style={{ color: 'var(--text-secondary)', margin: '4px 0 0 0', fontSize: '13px' }}>
                  {isEs 
                    ? 'Se requiere configurar una API Key de VirusTotal o AlienVault OTX para obtener el análisis de reputación automático de los siguientes IoCs extraídos:'
                    : 'A VirusTotal or AlienVault OTX API Key must be configured to automatically fetch reputation analysis for the following extracted IoCs:'}
                </p>
              </div>
            </div>
            
            {result.email_extracted_urls && result.email_extracted_urls.length > 0 && (
              <div style={{ marginBottom: '12px' }}>
                <h5 style={{ color: 'var(--cyan)', fontSize: '12px', marginBottom: '8px' }}>URLs ({result.email_extracted_urls.length})</h5>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {result.email_extracted_urls.slice(0, 10).map((url, idx) => (
                    <span key={idx} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)', padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      {url.length > 40 ? url.substring(0, 40) + '...' : url}
                    </span>
                  ))}
                  {result.email_extracted_urls.length > 10 && <span style={{ fontSize: '11px', color: 'var(--text-muted)', alignSelf: 'center' }}>+ {result.email_extracted_urls.length - 10} more</span>}
                </div>
              </div>
            )}

            {result.email_extracted_ips && result.email_extracted_ips.length > 0 && (
              <div>
                <h5 style={{ color: 'var(--cyan)', fontSize: '12px', marginBottom: '8px' }}>IP Addresses ({result.email_extracted_ips.length})</h5>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {result.email_extracted_ips.slice(0, 10).map((ip, idx) => (
                    <span key={idx} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-subtle)', padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      {ip}
                    </span>
                  ))}
                  {result.email_extracted_ips.length > 10 && <span style={{ fontSize: '11px', color: 'var(--text-muted)', alignSelf: 'center' }}>+ {result.email_extracted_ips.length - 10} more</span>}
                </div>
              </div>
            )}
            
            <div style={{ marginTop: '16px', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
              <button className="btn btn--secondary" style={{ fontSize: '11px', padding: '8px 16px', height: 'auto' }}>
                {isEs ? '⚙️ Configurar APIs en Ajustes' : '⚙️ Configure APIs in Settings'}
              </button>
            </div>
          </div>
        </div>
      )}

      
      </div>

      <div style={{ display: activeTab === "forensics" ? "block" : "none" }}>

      {/* Email Forensic Details Section */}
      {result.scan_type === 'email' && (
        <EmailScanResults 
          result={result} 
          isEs={isEs} 
          getUrlStatus={getUrlStatus} 
          getFileStatus={getFileStatus} 
          AttachmentTree={AttachmentTree} 
          zoomLevel={zoomLevel}
          renderZoomControls={renderZoomControls}
        />
      )}
      
      {result.scan_type !== 'email' && (result.email_extracted_headers || result.email_extracted_ips?.length > 0 || result.email_extracted_urls?.length > 0 || result.email_extracted_emails?.length > 0 || result.email_attachment_tree?.length > 0) && (
        <div style={{ marginBottom: '32px' }}>
          <div 
            onClick={() => setShowOuterForensics(!showOuterForensics)}
            className="results-panel__section-title"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', userSelect: 'none' }}
          >
            <span>
              {result.scan_type === 'document' 
                ? `🔗 ${isEs ? 'Enlaces y Conexiones Detectadas' : 'Document Links & Discovered Connections'}`
                : `📧 ${isEs ? 'Análisis Forense de Correo Detallado' : 'Email Forensic Triaging Details'}`}
            </span>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 'normal' }}>
              {showOuterForensics ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
            </span>
          </div>
          
          {showOuterForensics && (
            <div className="card" style={{ padding: '24px', background: 'rgba(11, 15, 25, 0.65)' }}>
            
            {/* 1. Extracted Email Headers */}
            {result.email_extracted_headers && (
              <div style={{ marginBottom: '24px' }}>
                <h4 
                  onClick={() => setShowHeadersCard(!showHeadersCard)}
                  style={{ 
                    color: 'var(--cyan)', 
                    fontSize: '14px', 
                    marginBottom: '12px', 
                    borderBottom: '1px solid rgba(96, 165, 250, 0.2)', 
                    paddingBottom: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  <span>📨 {isEs ? 'Cabeceras de Correo Extraídas' : 'Extracted Email Headers'}</span>
                  <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{showHeadersCard ? '▲ COMPRIMIR' : '▼ DESGLOSAR'}</span>
                </h4>
                {showHeadersCard && (
                  <>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '12px', fontSize: '13px', marginBottom: '12px' }}>
                      <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '8px 12px', borderRadius: '6px' }}>
                        <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase' }}>{isEs ? 'De (Sender)' : 'From'}</span>
                        <strong style={{ fontFamily: 'var(--font-mono)' }}>{result.email_extracted_headers.From || 'Unknown'}</strong>
                      </div>
                      <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '8px 12px', borderRadius: '6px' }}>
                        <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase' }}>{isEs ? 'Asunto (Subject)' : 'Subject'}</span>
                        <strong style={{ color: 'var(--text-primary)' }}>{result.email_extracted_headers.Subject || '(No Subject)'}</strong>
                      </div>
                      {result.email_extracted_headers['Reply-To'] && (
                        <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '8px 12px', borderRadius: '6px' }}>
                          <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase' }}>Reply-To</span>
                          <strong style={{ fontFamily: 'var(--font-mono)' }}>{result.email_extracted_headers['Reply-To']}</strong>
                        </div>
                      )}
                      {result.email_extracted_headers['Return-Path'] && (
                        <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '8px 12px', borderRadius: '6px' }}>
                          <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px', textTransform: 'uppercase' }}>Return-Path</span>
                          <strong style={{ fontFamily: 'var(--font-mono)' }}>{result.email_extracted_headers['Return-Path']}</strong>
                        </div>
                      )}
                    </div>
                    
                    {result.email_extracted_headers.Raw && (
                      <details style={{ cursor: 'pointer' }}>
                        <summary style={{ fontSize: '12px', color: 'var(--cyan)', fontWeight: 600 }}>
                          ⚙️ {isEs ? 'Ver Cabeceras Completas (Raw)' : 'Show Full Raw Headers'}
                        </summary>
                        <pre style={{
                          marginTop: '10px',
                          background: '#040711',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: '4px',
                          padding: '12px',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '11px',
                          maxHeight: '200px',
                          overflow: 'auto',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all',
                          textAlign: 'left'
                        }}>
                          {result.email_extracted_headers.Raw}
                        </pre>
                      </details>
                    )}
                  </>
                )}
              </div>
            )}

            {/* 2. Discovered IPs */}
            {result.email_extracted_ips && result.email_extracted_ips.length > 0 && (
              <div style={{ marginBottom: '24px' }}>
                <h4 
                  onClick={() => setShowIpsCard(!showIpsCard)}
                  style={{ 
                    color: 'var(--cyan)', 
                    fontSize: '14px', 
                    marginBottom: '12px', 
                    borderBottom: '1px solid rgba(96, 165, 250, 0.2)', 
                    paddingBottom: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  <span>🌐 {isEs ? 'Direcciones IP Detectadas' : 'Discovered IP Addresses'} ({result.email_extracted_ips.length})</span>
                  <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{showIpsCard ? '▲ COMPRIMIR' : '▼ DESGLOSAR'}</span>
                </h4>
                {showIpsCard && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {result.email_extracted_ips.map((ip) => {
                      const abuseData = result.third_party_results?.abuseipdb_ips?.[ip];
                      return (
                        <div key={ip} style={{
                          background: 'rgba(255, 255, 255, 0.02)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: '6px',
                          padding: '12px 16px',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          flexWrap: 'wrap',
                          gap: '12px'
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontSize: '14px' }}>🔌</span>
                            <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontSize: '13px' }}>{ip}</strong>
                          </div>
                          
                          {abuseData ? (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '12px' }}>
                              {abuseData.country && (
                                <span>🏳️ <strong>{abuseData.country}</strong></span>
                              )}
                              {abuseData.isp && (
                                <span style={{ color: 'var(--text-secondary)' }}>ISP: <strong>{abuseData.isp}</strong></span>
                              )}
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>
                                  {isEs ? 'Reputación de Abuso:' : 'Abuse Score:'}
                                </span>
                                <span style={{
                                  padding: '2px 8px',
                                  borderRadius: '4px',
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  background: abuseData.score > 20 ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                  color: abuseData.score > 20 ? 'var(--risk-high)' : 'var(--risk-low)',
                                  border: `1px solid ${abuseData.score > 20 ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`
                                }}>
                                  {abuseData.score}%
                                </span>
                              </div>
                            </div>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                              {isEs ? 'Reputación no comprobada (Escaneo externo inactivo)' : 'Reputation unchecked (External feeds off)'}
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* 3. Discovered URLs */}
            {result.email_extracted_urls && result.email_extracted_urls.length > 0 && (
              <div style={{ marginBottom: '24px' }}>
                <h4 
                  onClick={() => setShowUrlsCard(!showUrlsCard)}
                  style={{ 
                    color: 'var(--cyan)', 
                    fontSize: '14px', 
                    marginBottom: '12px', 
                    borderBottom: '1px solid rgba(96, 165, 250, 0.2)', 
                    paddingBottom: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  <span>🔗 {isEs ? 'Enlaces URL Detectados' : 'Discovered Link URLs'} ({result.email_extracted_urls.length})</span>
                  <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{showUrlsCard ? '▲ COMPRIMIR' : '▼ DESGLOSAR'}</span>
                </h4>
                {showUrlsCard && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    {result.email_extracted_urls.map((url) => {
                      const urlscanData = result.third_party_results?.urlscan_urls?.[url];
                      return (
                        <div key={url} style={{
                          background: 'rgba(255, 255, 255, 0.02)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: '6px',
                          padding: '12px 16px',
                          textAlign: 'left'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '16px', flexWrap: 'wrap', marginBottom: urlscanData ? '12px' : '0' }}>
                            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                              <a href={url} target="_blank" rel="noopener noreferrer" style={{
                                fontFamily: 'var(--font-mono)',
                                color: 'var(--cyan)',
                                fontSize: '12px',
                                wordBreak: 'break-all',
                                textDecoration: 'none'
                              }}>
                                {url} ↗
                              </a>
                              {(() => {
                                const urlStatus = getUrlStatus(url);
                                return urlStatus ? (
                                  <span style={{ 
                                    fontSize: '10px', 
                                    fontWeight: 'bold', 
                                    color: urlStatus.color, 
                                    padding: '1px 6px',
                                    background: 'rgba(255, 255, 255, 0.03)',
                                    border: `1px solid ${urlStatus.color}33`,
                                    borderRadius: '4px',
                                    display: 'inline-flex',
                                    alignItems: 'center'
                                  }}>
                                    {urlStatus.label}
                                  </span>
                                ) : null;
                              })()}
                            </div>
                            
                            {urlscanData && urlscanData.result_url && (
                              <a 
                                href={urlscanData.result_url} 
                                target="_blank" 
                                rel="noopener noreferrer" 
                                className="btn btn--secondary"
                                style={{ height: '26px', fontSize: '11px', padding: '0 8px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center' }}
                              >
                                🖥️ View urlscan.io Report ↗
                              </a>
                            )}
                          </div>

                          {urlscanData ? (
                            <div>
                              {urlscanData.screenshot_url && (
                                <div style={{ marginTop: '8px' }}>
                                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                                    🖥️ Sandbox Page Screenshot (urlscan.io):
                                  </div>
                                  <img 
                                    src={urlscanData.screenshot_url} 
                                    alt="URL Sandbox Screenshot" 
                                    style={{
                                      maxWidth: '100%',
                                      maxHeight: '220px',
                                      borderRadius: '4px',
                                      border: '1px solid rgba(255,255,255,0.08)',
                                      display: 'block'
                                    }}
                                    onError={(e) => { e.target.style.display = 'none'; }}
                                  />
                                </div>
                              )}
                            </div>
                          ) : (
                            <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
                              {isEs ? 'Sin escaneo en sandbox externo' : 'No external sandbox scan triggered.'}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* 3b. Discovered Emails */}
            {result.email_extracted_emails && result.email_extracted_emails.length > 0 && (
              <div style={{ marginBottom: '24px' }}>
                <h4 
                  onClick={() => setShowEmailsCard(!showEmailsCard)}
                  style={{ 
                    color: 'var(--cyan)', 
                    fontSize: '14px', 
                    marginBottom: '12px', 
                    borderBottom: '1px solid rgba(96, 165, 250, 0.2)', 
                    paddingBottom: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  <span>📨 {isEs ? 'Correos Electrónicos Detectados' : 'Discovered Email Addresses'} ({result.email_extracted_emails.length})</span>
                  <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{showEmailsCard ? '▲ COMPRIMIR' : '▼ DESGLOSAR'}</span>
                </h4>
                {showEmailsCard && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {result.email_extracted_emails.map((email) => (
                      <div key={email} style={{
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: '6px',
                        padding: '12px 16px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        flexWrap: 'wrap',
                        gap: '12px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontSize: '14px' }}>✉️</span>
                          <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontSize: '13px' }}>{email}</strong>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* 4. ZIP-Aware Attachment Tree */}
            {result.email_attachment_tree && result.email_attachment_tree.length > 0 && (
              <div>
                <h4 
                  onClick={() => setShowAttachmentsCard(!showAttachmentsCard)}
                  style={{ 
                    color: 'var(--cyan)', 
                    fontSize: '14px', 
                    marginBottom: '12px', 
                    borderBottom: '1px solid rgba(96, 165, 250, 0.2)', 
                    paddingBottom: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  <span>📎 {isEs ? 'Estructura de Archivos Adjuntos' : 'Email Attachments Tree Structure'} ({result.email_attachment_tree.length})</span>
                  <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{showAttachmentsCard ? '▲ COMPRIMIR' : '▼ DESGLOSAR'}</span>
                </h4>
                {showAttachmentsCard && (
                  <>
                    <AttachmentTree tree={result.email_attachment_tree} getFileStatus={getFileStatus} />

                    {/* VirusTotal attachment status */}
                    {result.third_party_results?.vt_attachments && (
                      <div style={{ marginTop: '16px', background: 'rgba(6, 182, 212, 0.05)', border: '1px solid rgba(6, 182, 212, 0.15)', borderRadius: '6px', padding: '12px 16px' }}>
                        <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--cyan)', marginBottom: '8px' }}>
                          🛡️ VirusTotal Attachment Reputation Results:
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                          {Object.entries(result.third_party_results.vt_attachments).map(([name, vtData]) => (
                            <div key={name} style={{ fontSize: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{name}</span>
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{
                                  padding: '1px 6px',
                                  borderRadius: '4px',
                                  fontSize: '10px',
                                  fontWeight: 700,
                                  background: vtData.malicious_count > 0 ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                  color: vtData.malicious_count > 0 ? 'var(--risk-high)' : 'var(--risk-low)'
                                }}>
                                  {vtData.score || 'Clean'}
                                </span>
                                {vtData.permalink && (
                                  <a href={vtData.permalink} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--cyan)', textDecoration: 'none' }}>↗</a>
                                )}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    )}

      {/* Analyzer Breakdown */}
      {result.analyzer_breakdown && result.analyzer_breakdown.length > 0 && (
        <div style={{ marginBottom: '24px' }}>
          <div 
            onClick={() => setShowBreakdownCard(!showBreakdownCard)}
            className="results-panel__section-title"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', userSelect: 'none' }}
          >
            <span>{t?.breakdown_title || '📊 Analyzer Breakdown'}</span>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 'normal' }}>
              {showBreakdownCard ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
            </span>
          </div>
          {showBreakdownCard && (
            <div className="breakdown">
              {result.analyzer_breakdown.map((b, i) => (
                <div key={i} className="breakdown__item">
                  <div className="breakdown__name">{b.analyzer.replace('_', ' ')}</div>
                  <div className="breakdown__score" style={{ 
                    color: b.score > 50 ? 'var(--risk-high)' : b.score > 25 ? 'var(--risk-medium)' : 'var(--risk-low)',
                  }}>
                    {b.score.toFixed(0)}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Weight: {(b.weight * 100).toFixed(0)}% · {b.findings_count} finding(s)
                  </div>
                  <div className="breakdown__bar">
                    <div 
                      className="breakdown__bar-fill" 
                      style={{ width: `${Math.min(b.score, 100)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}


      {/* Findings */}
      <div id="findings-section" className="results-panel__section-title">
        {t?.findings_title || '📋 Findings'} ({result.findings?.length || 0})
      </div>
      
      {result.findings && result.findings.length > 0 ? (
        (() => {
          const isEs = t?.scan_button === 'Escanear';
          const confirmed = result.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
          const suspicious = result.findings.filter(f => f.severity === 'medium' || f.severity === 'low');
          const info = result.findings.filter(f => f.severity === 'info');
          
          return (
            <div>
              {/* 1. Confirmed Malicious */}
              {confirmed.length > 0 && (
                <div style={{ marginBottom: '24px' }}>
                  <div 
                    onClick={() => setShowConfirmedFindings(!showConfirmedFindings)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      cursor: 'pointer',
                      userSelect: 'none',
                      padding: '12px 16px',
                      background: 'rgba(239, 68, 68, 0.08)',
                      borderLeft: '4px solid var(--risk-high)',
                      borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                      marginBottom: '14px',
                      border: '1px solid rgba(239, 68, 68, 0.15)',
                      borderLeftWidth: '4px'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <span style={{ fontSize: '20px' }}>🚨</span>
                      <div>
                        <strong style={{ color: 'var(--text-primary)', fontSize: '13px', display: 'block', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                          {isEs ? 'Evidencia Maliciosa Confirmada' : 'Confirmed Malicious Evidence'} ({confirmed.length})
                        </strong>
                        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                          {isEs 
                            ? 'Amenazas confirmadas y firmas maliciosas que indican un riesgo real inmediato.' 
                            : 'Confirmed high-severity indicators and threats that present a confirmed risk.'}
                        </span>
                      </div>
                    </div>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {showConfirmedFindings ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
                    </span>
                  </div>
                  {showConfirmedFindings && confirmed
                    .sort((a, b) => b.score_impact - a.score_impact)
                    .map((f, i) => <FindingCard key={`conf-${i}`} finding={f} />)}
                </div>
              )}

              {/* 2. Suspicious Behaviors / Human Criteria */}
              {suspicious.length > 0 && (
                <div style={{ marginBottom: '24px' }}>
                  <div 
                    onClick={() => setShowSuspiciousFindings(!showSuspiciousFindings)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      cursor: 'pointer',
                      userSelect: 'none',
                      padding: '12px 16px',
                      background: 'rgba(245, 158, 11, 0.08)',
                      borderLeft: '4px solid var(--risk-medium)',
                      borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                      marginBottom: '14px',
                      border: '1px solid rgba(245, 158, 11, 0.15)',
                      borderLeftWidth: '4px'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <span style={{ fontSize: '20px' }}>⚠️</span>
                      <div>
                        <strong style={{ color: 'var(--text-primary)', fontSize: '13px', display: 'block', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                          {isEs ? 'Comportamiento Sospechoso / Criterio Humano' : 'Suspicious Behavior / Human Triage Required'} ({suspicious.length})
                        </strong>
                        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                          {isEs 
                            ? 'Comportamientos anómalos detectados. Requiere criterio y análisis humano para descartar un posible Falso Positivo.' 
                            : 'Anomalous indicators detected. Requires human analysis and discretion to confirm or rule out a False Positive.'}
                        </span>
                      </div>
                    </div>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {showSuspiciousFindings ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
                    </span>
                  </div>
                  {showSuspiciousFindings && suspicious
                    .sort((a, b) => b.score_impact - a.score_impact)
                    .map((f, i) => <FindingCard key={`susp-${i}`} finding={f} />)}
                </div>
              )}

              {/* 3. General Information */}
              {info.length > 0 && (
                <div style={{ marginBottom: '24px' }}>
                  <div 
                    onClick={() => setShowInfoFindings(!showInfoFindings)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      cursor: 'pointer',
                      userSelect: 'none',
                      padding: '10px 16px',
                      background: 'rgba(96, 165, 250, 0.08)',
                      borderLeft: '4px solid var(--severity-info)',
                      borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                      marginBottom: '14px',
                      border: '1px solid rgba(96, 165, 250, 0.15)',
                      borderLeftWidth: '4px'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <span style={{ fontSize: '18px' }}>ℹ️</span>
                      <div>
                        <strong style={{ color: 'var(--text-primary)', fontSize: '13px', display: 'block', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                          {isEs ? 'Información General y Metadatos' : 'General Info & Metadata'} ({info.length})
                        </strong>
                      </div>
                    </div>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {showInfoFindings ? (isEs ? '▲ COMPRIMIR' : '▲ COLLAPSE') : (isEs ? '▼ DESGLOSAR' : '▼ EXPAND')}
                    </span>
                  </div>
                  {showInfoFindings && info.map((f, i) => <FindingCard key={`info-${i}`} finding={f} />)}
                </div>
              )}
            </div>
          );
        })()
      ) : (
        <div style={{ color: 'var(--text-muted)', padding: '20px', textAlign: 'center' }}>
          {t?.no_findings || 'No findings to display.'}
        </div>
      )}

      
      </div>

      {/* Debug Panel */}
      <DebugPanel debugTrace={result.debug_trace} t={t} />
    </div>
  );
}
