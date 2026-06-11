import React, { useState } from 'react';
import FindingCard from './FindingCard';

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

export default function EmailScanResults({ result, isEs, getUrlStatus, getFileStatus, AttachmentTree, zoomLevel = 1.0, renderZoomControls = null }) {
  const [showRaw, setShowRaw] = useState(false);
  
  const eh = result.email_extracted_headers || {};
  const hasHeaders = Object.keys(eh).length > 0;
  
  const parseReceivedHops = (rawText) => {
    if (!rawText) return [];
    const lines = rawText.split('\n');
    const hops = [];
    let currentHop = '';
    for (let line of lines) {
      if (line.toLowerCase().startsWith('received:')) {
        if (currentHop) hops.push(currentHop);
        currentHop = line.replace(/^received:\s*/i, '');
      } else if (currentHop && (line.startsWith(' ') || line.startsWith('\t'))) {
        currentHop += ' ' + line.trim();
      } else if (currentHop) {
        hops.push(currentHop);
        currentHop = '';
      }
    }
    if (currentHop) hops.push(currentHop);
    return hops;
  };
  const receivedHops = parseReceivedHops(eh.Raw);

  const parseAllHeaders = (rawText) => {
    if (!rawText) return [];
    const lines = rawText.split('\n');
    const headers = [];
    let currentKey = '';
    let currentValue = '';
    for (let line of lines) {
      if (line.match(/^[A-Za-z0-9-]+:/)) {
        if (currentKey) {
          headers.push([currentKey, currentValue.trim()]);
        }
        const splitIdx = line.indexOf(':');
        currentKey = line.substring(0, splitIdx).trim();
        currentValue = line.substring(splitIdx + 1);
      } else if (currentKey && (line.startsWith(' ') || line.startsWith('\t'))) {
        currentValue += ' ' + line.trim();
      }
    }
    if (currentKey) {
      headers.push([currentKey, currentValue.trim()]);
    }
    return headers;
  };

  const allParsedHeaders = parseAllHeaders(eh.Raw);

  const excludeKeys = ['subject', 'from', 'to', 'date', 'return-path', 'message-id', 'content-type', 'mime-version', 'received'];
  
  const criticalKeys = [
    'authentication-results', 'received-spf', 'dkim-signature', 'x-mailer', 
    'x-originating-ip', 'x-spam-status', 'x-spam-score', 'arc-authentication-results',
    'arc-message-signature', 'arc-seal', 'list-unsubscribe', 'x-virus-scanned',
    'x-report-abuse', 'x-sender-ip', 'x-antiabuse', 'reply-to', 'x-phish-score', 'x-ms-exchange-organization-scl'
  ];

  // Remove exact duplicates and take top 10 most critical for SOC
  const uniqueHeaders = [];
  const seenKeys = new Set();
  
  allParsedHeaders.forEach(([k, v]) => {
    const lowerK = k.toLowerCase();
    if (!excludeKeys.includes(lowerK) && !seenKeys.has(lowerK)) {
      uniqueHeaders.push([k, v]);
      seenKeys.add(lowerK);
    }
  });

  const topHeaders = uniqueHeaders
    .sort((a, b) => {
      const aCrit = criticalKeys.includes(a[0].toLowerCase());
      const bCrit = criticalKeys.includes(b[0].toLowerCase());
      if (aCrit && !bCrit) return -1;
      if (!aCrit && bCrit) return 1;
      return 0;
    })
    .slice(0, 10);
  
  return (
    <div style={{ marginTop: '24px' }}>
      {/* METADATA SECTION */}
      {hasHeaders && (
        <div className="card" style={{ padding: '24px', marginBottom: '24px' }}>
          <h3 style={{ color: 'var(--cyan)', fontSize: '15px', marginBottom: '16px', borderBottom: '1px solid rgba(96, 165, 250, 0.2)', paddingBottom: '8px' }}>
            📋 METADATA
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px', fontSize: '12px' }}>
            <div><strong>Subject:</strong> <span style={{ color: 'var(--text-primary)' }}>{eh.Subject || 'N/A'}</span></div>
            <div><strong>Sender:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{eh.From || 'N/A'}</span> <CopyButton text={eh.From || ''} /></div>
            <div><strong>Creation Date:</strong> <span>{eh.Date || 'N/A'}</span></div>
            <div><strong>Return-Path:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{eh['Return-Path'] || 'N/A'}</span></div>
            <div><strong>Sender IP:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{eh.SenderIP || 'N/A'}</span> {eh.SenderIP && <CopyButton text={eh.SenderIP} />}</div>
            <div><strong>Message ID:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{eh['Message-ID'] || 'N/A'}</span></div>
            <div style={{ display: 'flex', gap: '16px', gridColumn: '1 / -1', background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
              <div><strong>SPF:</strong> <span style={{ color: eh.SPF === 'PASS' ? 'var(--risk-low)' : eh.SPF === 'FAIL' ? 'var(--risk-high)' : 'var(--risk-medium)' }}>{eh.SPF || 'N/A'}</span></div>
              <div><strong>DKIM:</strong> <span style={{ color: eh.DKIM === 'PASS' ? 'var(--risk-low)' : eh.DKIM === 'FAIL' ? 'var(--risk-high)' : 'var(--risk-medium)' }}>{eh.DKIM || 'N/A'}</span></div>
              <div><strong>DMARC:</strong> <span style={{ color: eh.DMARC === 'PASS' ? 'var(--risk-low)' : eh.DMARC === 'FAIL' ? 'var(--risk-high)' : 'var(--risk-medium)' }}>{eh.DMARC || 'N/A'}</span></div>
            </div>
          </div>
        </div>
      )}

      {/* VISUAL PREVIEW SECTION */}
      {result.email_body_html && (
        <div className="card" style={{ padding: '24px', marginBottom: '24px' }}>
          <h3 style={{ color: 'var(--cyan)', fontSize: '15px', marginBottom: '16px', borderBottom: '1px solid rgba(96, 165, 250, 0.2)', paddingBottom: '8px' }}>
            👁️ VISUAL PREVIEW
          </h3>
          {renderZoomControls && renderZoomControls()}
          <div style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'top left', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '20px', background: '#ffffff', position: 'relative', overflow: 'hidden' }}>
            <iframe 
              srcDoc={result.email_body_html} 
              style={{ width: '100%', minHeight: '600px', border: 'none', background: '#ffffff' }}
              sandbox=""
              title="Email Body Preview"
            />
          </div>
        </div>
      )}

      {/* EMAIL FORENSIC TRIAGING DETAILS */}
      <div className="card" style={{ padding: '24px', marginBottom: '24px' }}>
        <h3 style={{ color: 'var(--cyan)', fontSize: '15px', marginBottom: '16px', borderBottom: '1px solid rgba(96, 165, 250, 0.2)', paddingBottom: '8px' }}>
          🔍 EMAIL FORENSIC TRIAGING DETAILS
        </h3>
        
        {eh.Raw && (
          <div style={{ marginBottom: '20px' }}>
            <div 
              onClick={() => setShowRaw(!showRaw)}
              style={{ cursor: 'pointer', display: 'flex', justifyContent: 'space-between', background: 'rgba(255,255,255,0.05)', padding: '8px 12px', borderRadius: '4px', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)', fontSize: '12px' }}
            >
              <strong>⚙️ Raw Full Headers</strong>
              <span>{showRaw ? '▲ Collapse' : '▼ Expand'}</span>
            </div>
            {showRaw && (
              <pre style={{ marginTop: '10px', background: '#040711', padding: '12px', fontSize: '10px', maxHeight: '300px', overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', wordWrap: 'break-word', border: '1px solid var(--border-subtle)' }}>
                {eh.Raw}
              </pre>
            )}
          </div>
        )}

        {topHeaders.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <h4 style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '8px' }}>Top Critical Headers</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {topHeaders.map(([k, v]) => (
                <div key={k} style={{ background: 'rgba(255,255,255,0.02)', padding: '6px 12px', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  <span style={{ color: 'var(--cyan)' }}>{k}:</span> <span style={{ wordBreak: 'break-all' }}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {receivedHops.length > 0 && (
          <div style={{ marginBottom: '24px' }}>
            <h4 style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '12px' }}>Server IP Hops (Received Chain) - {receivedHops.length} hops</h4>
            <div style={{ display: 'flex', flexDirection: 'column', position: 'relative', paddingLeft: '16px' }}>
              <div style={{ position: 'absolute', top: 0, bottom: 0, left: '7px', width: '2px', background: 'rgba(96, 165, 250, 0.2)' }}></div>
              {receivedHops.map((hop, idx) => (
                <div key={idx} style={{ position: 'relative', marginBottom: idx === receivedHops.length - 1 ? 0 : '16px' }}>
                  <div style={{ position: 'absolute', left: '-13px', top: '12px', width: '10px', height: '10px', borderRadius: '50%', background: 'var(--cyan)', border: '2px solid #070a13' }}></div>
                  <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px 14px', border: '1px solid var(--border-subtle)', borderRadius: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                    <div style={{ color: 'var(--text-primary)', marginBottom: '4px', fontWeight: 'bold', display: 'flex', justifyContent: 'space-between' }}>
                      <span>Hop {receivedHops.length - idx}</span>
                      {idx === 0 && <span style={{ color: 'var(--risk-low)', fontSize: '10px' }}>[Destination]</span>}
                      {idx === receivedHops.length - 1 && <span style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>[Origin]</span>}
                    </div>
                    <div style={{ color: 'var(--text-secondary)' }}>{hop}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {result.email_extracted_ips && result.email_extracted_ips.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <h4 style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '8px' }}>Discovered IPs ({result.email_extracted_ips.length})</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {result.email_extracted_ips.map(ip => (
                <div key={ip} style={{ display: 'flex', alignItems: 'center', gap: '12px', background: 'rgba(255,255,255,0.02)', padding: '6px 12px', border: '1px solid var(--border-subtle)', borderRadius: '4px' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{ip}</span>
                  <CopyButton text={ip} />
                </div>
              ))}
            </div>
          </div>
        )}

        {result.email_extracted_urls && result.email_extracted_urls.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <h4 style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '8px' }}>Discovered Link URLs ({result.email_extracted_urls.length})</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {result.email_extracted_urls.map(url => (
                <div key={url} style={{ display: 'flex', alignItems: 'center', gap: '12px', background: 'rgba(255,255,255,0.02)', padding: '6px 12px', border: '1px solid var(--border-subtle)', borderRadius: '4px' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', wordBreak: 'break-all' }}>{url}</span>
                  <CopyUrlGroup url={url} />
                </div>
              ))}
            </div>
          </div>
        )}

        {result.email_extracted_emails && result.email_extracted_emails.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <h4 style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '8px' }}>Discovered Email Addresses ({result.email_extracted_emails.length})</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {result.email_extracted_emails.map(email => (
                <div key={email} style={{ display: 'flex', alignItems: 'center', gap: '12px', background: 'rgba(255,255,255,0.02)', padding: '6px 12px', border: '1px solid var(--border-subtle)', borderRadius: '4px' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{email}</span>
                  <CopyButton text={email} />
                </div>
              ))}
            </div>
          </div>
        )}

        {result.email_attachment_tree && result.email_attachment_tree.length > 0 && (
          <div>
            <h4 style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '8px' }}>Email Attachments Tree Structure ({result.email_attachment_tree.length})</h4>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: '16px', border: '1px solid var(--border-subtle)', borderRadius: '4px' }}>
              <AttachmentTree tree={result.email_attachment_tree} getFileStatus={getFileStatus} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
