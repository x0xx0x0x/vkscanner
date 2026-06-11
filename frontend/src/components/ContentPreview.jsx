import React, { useState, useRef } from 'react';

/**
 * ContentPreview — renders a visual snapshot of the scanned target.
 *
 * Supports three scan types:
 *  - url:      url_site_preview (HTML structure text) rendered in a sandboxed iframe
 *  - email:    email_body_html rendered in a sandboxed iframe (with threat overlay)
 *  - document: document_screenshot (base64 PNG) of the first page
 */
export default function ContentPreview({ result, t }) {
  const [zoom, setZoom] = useState(1.0);
  const [tab, setTab] = useState('preview');   // 'preview' | 'source'
  const [copied, setCopied] = useState(false);
  const iframeRef = useRef(null);
  const isEs = t?.scan_button === 'Escanear';

  if (!result) return null;

  const scanType = result.scan_type;

  /* ── Determine what content we have ── */
  const hasDocScreenshot = scanType === 'document' && result.document_screenshot;
  const hasEmailHtml     = scanType === 'email'    && result.email_body_html;
  const hasUrlPreview    = scanType === 'url'      && result.url_site_preview;

  if (!hasDocScreenshot && !hasEmailHtml && !hasUrlPreview) return null;

  /* ── Risk color border ── */
  const score = result.risk_score ?? 0;
  const riskBorder =
    score >= 76 ? 'rgba(185, 28, 28, 0.55)' :
    score >= 51 ? 'rgba(239, 68, 68, 0.45)' :
    score >= 26 ? 'rgba(217, 119, 6, 0.45)' :
                  'rgba(16, 185, 129, 0.3)';

  const riskLabel =
    score >= 76 ? (isEs ? 'CRÍTICO' : 'CRITICAL') :
    score >= 51 ? (isEs ? 'ALTO' : 'HIGH') :
    score >= 26 ? (isEs ? 'MEDIO' : 'MEDIUM') :
                  (isEs ? 'BAJO' : 'LOW');

  const riskColor =
    score >= 76 ? 'var(--risk-critical)' :
    score >= 51 ? 'var(--risk-high)' :
    score >= 26 ? 'var(--risk-medium)' :
                  'var(--risk-low)';

  /* ── Zoom helpers ── */
  const zoomIn  = () => setZoom(z => Math.min(z + 0.15, 2.0));
  const zoomOut = () => setZoom(z => Math.max(z - 0.15, 0.4));
  const zoomReset = () => setZoom(1.0);

  /* ── Source copy helper ── */
  const handleCopySource = (src) => {
    navigator.clipboard.writeText(src);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  /* ── Shared styles ── */
  const containerStyle = {
    border: `1px solid ${riskBorder}`,
    borderRadius: 'var(--radius-md)',
    overflow: 'hidden',
    background: 'rgba(10, 12, 16, 0.7)',
    boxShadow: `0 0 24px ${riskBorder}`,
    position: 'relative',
  };

  const browserBarStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 14px',
    background: 'rgba(17, 20, 28, 0.95)',
    borderBottom: `1px solid ${riskBorder}`,
    backdropFilter: 'blur(8px)',
  };

  const trafficLightStyle = (color) => ({
    width: 11,
    height: 11,
    borderRadius: '50%',
    background: color,
    opacity: 0.8,
  });

  /* ── Toolbar ── */
  const ZoomBar = () => (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '6px',
      background: 'rgba(2, 6, 23, 0.7)',
      borderRadius: '6px',
      padding: '4px 10px',
      border: '1px solid var(--border-subtle)',
    }}>
      <button onClick={zoomOut} title="Zoom out" style={btnStyle}>−</button>
      <span style={{ fontSize: '11px', color: 'var(--text-secondary)', minWidth: '36px', textAlign: 'center' }}>
        {Math.round(zoom * 100)}%
      </span>
      <button onClick={zoomIn} title="Zoom in" style={btnStyle}>+</button>
      <button onClick={zoomReset} style={{ ...btnStyle, color: 'var(--cyan)', fontSize: '10px' }}>↺</button>
    </div>
  );

  const btnStyle = {
    background: 'rgba(255,255,255,0.05)',
    border: '1px solid var(--border-subtle)',
    borderRadius: '4px',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    padding: '1px 7px',
    fontSize: '14px',
    lineHeight: '1.4',
  };

  const tabBtnStyle = (active) => ({
    padding: '4px 12px',
    fontSize: '11px',
    fontWeight: 700,
    cursor: 'pointer',
    border: 'none',
    borderRadius: '4px',
    background: active ? 'rgba(96, 165, 250, 0.18)' : 'transparent',
    color: active ? 'var(--cyan)' : 'var(--text-muted)',
    fontFamily: 'var(--font-sans)',
    letterSpacing: '0.5px',
    transition: 'all 0.2s',
  });

  /* ═══════════════════════════════════════════
     DOCUMENT — first-page PNG screenshot
  ═══════════════════════════════════════════ */
  if (hasDocScreenshot) {
    const src = `data:image/png;base64,${result.document_screenshot}`;
    return (
      <div style={{ marginBottom: '24px' }}>
        {/* Section header */}
        <div className="results-panel__section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>📄 {isEs ? 'Vista Previa del Documento (Primera Página)' : 'Document Preview (First Page)'}</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '4px', background: `${riskColor}22`, color: riskColor, border: `1px solid ${riskColor}55`, fontWeight: 700 }}>
              {riskLabel} {score}/100
            </span>
            <ZoomBar />
          </div>
        </div>

        <div style={containerStyle}>
          {/* Fake browser chrome */}
          <div style={browserBarStyle}>
            <div style={trafficLightStyle('#ef4444')} />
            <div style={trafficLightStyle('#f59e0b')} />
            <div style={trafficLightStyle('#10b981')} />
            <span style={{ marginLeft: '8px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', flex: 1 }}>
              📄 {result.target}
            </span>
            <a href={src} download={`${result.target}_preview.png`}
              style={{ fontSize: '11px', color: 'var(--cyan)', textDecoration: 'none', padding: '2px 8px', border: '1px solid rgba(96,165,250,0.3)', borderRadius: '4px', fontWeight: 700 }}>
              {isEs ? '⬇ Descargar' : '⬇ Download'}
            </a>
          </div>

          {/* Screenshot */}
          <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '520px', background: '#fff' }}>
            <img
              src={src}
              alt="Document first-page preview"
              style={{ display: 'block', transform: `scale(${zoom})`, transformOrigin: 'top left', width: `${100 / zoom}%`, transition: 'transform 0.2s' }}
            />
          </div>
        </div>
      </div>
    );
  }

  /* ═══════════════════════════════════════════
     EMAIL — HTML body rendered in sandbox iframe
  ═══════════════════════════════════════════ */
  if (hasEmailHtml) {
    const html = result.email_body_html;

    return (
      <div style={{ marginBottom: '24px' }}>
        <div className="results-panel__section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>📧 {isEs ? 'Vista Previa del Cuerpo del Correo' : 'Email Body Preview'}</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '4px', background: `${riskColor}22`, color: riskColor, border: `1px solid ${riskColor}55`, fontWeight: 700 }}>
              {riskLabel} {score}/100
            </span>
            <button style={tabBtnStyle(tab === 'preview')} onClick={() => setTab('preview')}>
              {isEs ? '👁 Vista' : '👁 Preview'}
            </button>
            <button style={tabBtnStyle(tab === 'source')} onClick={() => setTab('source')}>
              {isEs ? '</> HTML' : '</> Source'}
            </button>
          </div>
        </div>

        <div style={containerStyle}>
          {/* Browser bar */}
          <div style={browserBarStyle}>
            <div style={trafficLightStyle('#ef4444')} />
            <div style={trafficLightStyle('#f59e0b')} />
            <div style={trafficLightStyle('#10b981')} />
            <span style={{ marginLeft: '8px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', flex: 1 }}>
              📧 {result.email_extracted_headers?.From || result.target}
            </span>
            {/* Threat badge overlay */}
            <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: `${riskColor}22`, color: riskColor, border: `1px solid ${riskColor}55`, fontWeight: 700 }}>
              🛡 SANDBOXED
            </span>
          </div>

          {tab === 'preview' ? (
            <div style={{ position: 'relative' }}>
              {/* Threat risk overlay banner */}
              {score >= 26 && (
                <div style={{
                  position: 'absolute',
                  top: 0, left: 0, right: 0,
                  zIndex: 10,
                  background: score >= 51 ? 'rgba(185,28,28,0.88)' : 'rgba(180,83,9,0.85)',
                  padding: '6px 14px',
                  fontSize: '11px',
                  fontWeight: 700,
                  color: '#fff',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backdropFilter: 'blur(4px)',
                }}>
                  {score >= 51 ? '🚨' : '⚠️'}
                  {isEs
                    ? `Este correo tiene puntuación de riesgo ${score}/100. Los enlaces y formularios están desactivados.`
                    : `This email has a risk score of ${score}/100. Links and forms are disabled in sandbox.`}
                </div>
              )}
              <iframe
                ref={iframeRef}
                srcDoc={html}
                sandbox="allow-same-origin"
                title="Email body preview"
                style={{
                  display: 'block',
                  width: '100%',
                  height: '480px',
                  border: 'none',
                  marginTop: score >= 26 ? '32px' : '0',
                  background: '#fff',
                }}
              />
            </div>
          ) : (
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => handleCopySource(html)}
                style={{
                  position: 'absolute', top: '10px', right: '12px', zIndex: 5,
                  background: 'rgba(96,165,250,0.15)', border: '1px solid rgba(96,165,250,0.4)',
                  color: 'var(--cyan)', borderRadius: '4px', padding: '3px 10px',
                  fontSize: '11px', cursor: 'pointer', fontWeight: 700,
                }}>
                {copied ? '✓ COPIED' : 'COPY'}
              </button>
              <pre style={{
                margin: 0,
                padding: '16px',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                color: 'var(--text-secondary)',
                overflowX: 'auto',
                maxHeight: '480px',
                overflowY: 'auto',
                background: 'rgba(8, 11, 17, 0.95)',
                lineHeight: '1.6',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}>
                {html}
              </pre>
            </div>
          )}
        </div>
      </div>
    );
  }

  /* ═══════════════════════════════════════════
     URL — site structure preview
     url_site_preview = { title, forms, inputs, text_snippet, links_count, ... }
  ═══════════════════════════════════════════ */
  if (hasUrlPreview) {
    const p = result.url_site_preview;

    // Build a fake "screenshot" from the structured preview data
    const buildHtml = () => {
      const links = (p.links || []).slice(0, 8);
      const forms = (p.forms || []);
      const inputs = (p.inputs || []);
      const title = p.title || p.page_title || result.target;
      const snippet = p.text_snippet || p.body_text || '';

      return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; padding: 16px; background: #f8fafc; color: #0f172a; font-size: 13px; }
    h1  { font-size: 16px; margin: 0 0 4px; color: #0f172a; }
    .url { font-size: 11px; color: #2563eb; word-break: break-all; margin-bottom: 16px; }
    .section { margin-bottom: 14px; }
    .section h3 { font-size: 11px; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px; margin: 0 0 6px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
    .pill { display: inline-block; background: #e0f2fe; color: #0369a1; border-radius: 4px; padding: 2px 8px; font-size: 10px; margin: 2px; font-weight: 600; }
    .pill.form { background: #fef3c7; color: #92400e; }
    .pill.input { background: #ede9fe; color: #5b21b6; }
    .snippet { font-size: 12px; color: #475569; line-height: 1.5; background: #f1f5f9; padding: 10px 12px; border-radius: 6px; white-space: pre-wrap; word-break: break-word; }
    .stat { display: inline-block; margin-right: 14px; font-size: 11px; color: #64748b; }
    .stat strong { color: #0f172a; }
  </style>
</head>
<body>
  <h1>${title}</h1>
  <div class="url">${result.target}</div>

  <div class="section">
    <span class="stat">🔗 <strong>${p.links_count ?? (p.links || []).length}</strong> links</span>
    <span class="stat">📝 <strong>${forms.length}</strong> forms</span>
    <span class="stat">🔑 <strong>${inputs.length}</strong> inputs</span>
    ${p.has_password_field ? '<span class="stat">🔐 <strong>Password field</strong></span>' : ''}
    ${p.has_login_form ? '<span class="stat">🚪 <strong>Login form</strong></span>' : ''}
  </div>

  ${snippet ? `<div class="section"><h3>Page Snippet</h3><div class="snippet">${snippet.substring(0, 600)}${snippet.length > 600 ? '…' : ''}</div></div>` : ''}

  ${forms.length > 0 ? `<div class="section"><h3>Forms Detected</h3>${forms.slice(0, 4).map(f => `<span class="pill form">📝 ${f.action || 'anonymous form'}</span>`).join('')}</div>` : ''}

  ${inputs.length > 0 ? `<div class="section"><h3>Input Fields</h3>${inputs.slice(0, 8).map(i => `<span class="pill input">🔑 ${i.name || i.type || 'input'}</span>`).join('')}</div>` : ''}

  ${links.length > 0 ? `<div class="section"><h3>Links (sample)</h3>${links.map(l => `<span class="pill">${typeof l === 'string' ? l.substring(0, 50) : JSON.stringify(l).substring(0, 50)}</span>`).join('')}</div>` : ''}
</body>
</html>`;
    };

    const previewHtml = buildHtml();

    return (
      <div style={{ marginBottom: '24px' }}>
        <div className="results-panel__section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>🌐 {isEs ? 'Vista Previa del Sitio Web' : 'Website Content Preview'} {p.screenshots && p.screenshots.length > 0 && <span style={{fontSize: '11px', color: 'var(--cyan)', marginLeft: '8px'}}>(📸 Live Render)</span>}</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '4px', background: `${riskColor}22`, color: riskColor, border: `1px solid ${riskColor}55`, fontWeight: 700 }}>
              {riskLabel} {score}/100
            </span>
            <button style={tabBtnStyle(tab === 'preview')} onClick={() => setTab('preview')}>
              {isEs ? '👁 Vista' : '👁 Preview'}
            </button>
            <button style={tabBtnStyle(tab === 'source')} onClick={() => setTab('source')}>
              {isEs ? '⚙ Datos' : '⚙ Raw Data'}
            </button>
          </div>
        </div>

        <div style={containerStyle}>
          {/* Fake browser address bar */}
          <div style={browserBarStyle}>
            <div style={trafficLightStyle('#ef4444')} />
            <div style={trafficLightStyle('#f59e0b')} />
            <div style={trafficLightStyle('#10b981')} />
            <div style={{
              marginLeft: '8px',
              flex: 1,
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '6px',
              padding: '4px 10px',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              color: score >= 51 ? '#fca5a5' : 'var(--text-secondary)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}>
              {score >= 51 ? '🔴' : score >= 26 ? '⚠️' : '🔒'}
              <span style={{ wordBreak: 'break-all' }}>{result.target}</span>
            </div>
            <ZoomBar />
          </div>

          {tab === 'preview' ? (
            <div style={{ overflow: 'hidden', height: '440px', background: '#fff' }}>
              {score >= 26 && (
                <div style={{
                  background: score >= 51 ? 'rgba(185,28,28,0.9)' : 'rgba(180,83,9,0.88)',
                  padding: '5px 14px',
                  fontSize: '11px',
                  fontWeight: 700,
                  color: '#fff',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}>
                  {score >= 51 ? '🚨' : '⚠️'}
                  {isEs
                    ? `Sitio con riesgo ${score}/100. Vista reconstruida a partir de estructura heurística local — sin conexión real.`
                    : `Site risk score: ${score}/100. Preview rebuilt from local heuristic structure — no live connection.`}
                </div>
              )}
              {p.screenshots && p.screenshots.length > 0 ? (
                <div style={{ display: 'flex', overflowX: 'auto', gap: '16px', padding: '16px', height: '100%', boxSizing: 'border-box', background: '#0a0c10' }}>
                  {p.screenshots.map((shot, idx) => (
                    <div key={idx} style={{ flexShrink: 0, width: '90%', maxWidth: '800px', display: 'flex', flexDirection: 'column', border: '1px solid var(--border-subtle)', borderRadius: '8px', overflow: 'hidden', background: '#171c26' }}>
                      <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.05)', fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ wordBreak: 'break-all' }}>{shot.url}</span>
                        <span style={{ background: shot.type === 'final' ? 'var(--cyan)' : '#f59e0b', color: '#000', padding: '2px 6px', borderRadius: '4px', fontWeight: 'bold', fontSize: '9px', textTransform: 'uppercase' }}>
                          {shot.type || 'screenshot'}
                        </span>
                      </div>
                      <div style={{ flex: 1, overflow: 'auto', display: 'flex', justifyContent: 'center' }}>
                        <img 
                          src={`data:image/jpeg;base64,${shot.data}`} 
                          alt={`Screenshot of ${shot.url}`} 
                          style={{ 
                            transform: `scale(${zoom})`, 
                            transformOrigin: 'top center',
                            maxWidth: '100%', 
                            height: 'auto', 
                            objectFit: 'contain' 
                          }} 
                        />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <iframe
                  srcDoc={previewHtml}
                  sandbox=""
                  title="URL site preview"
                  style={{
                    display: 'block',
                    width: `${100 / zoom}%`,
                    height: score >= 26 ? '412px' : '440px',
                    border: 'none',
                    transform: `scale(${zoom})`,
                    transformOrigin: 'top left',
                    transition: 'transform 0.2s',
                  }}
                />
              )}
            </div>
          ) : (
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => handleCopySource(JSON.stringify(result.url_site_preview, null, 2))}
                style={{
                  position: 'absolute', top: '10px', right: '12px', zIndex: 5,
                  background: 'rgba(96,165,250,0.15)', border: '1px solid rgba(96,165,250,0.4)',
                  color: 'var(--cyan)', borderRadius: '4px', padding: '3px 10px',
                  fontSize: '11px', cursor: 'pointer', fontWeight: 700,
                }}>
                {copied ? '✓ COPIED' : 'COPY JSON'}
              </button>
              <pre style={{
                margin: 0, padding: '16px',
                fontFamily: 'var(--font-mono)', fontSize: '11px',
                color: 'var(--text-secondary)',
                overflowX: 'auto', maxHeight: '440px', overflowY: 'auto',
                background: 'rgba(8, 11, 17, 0.95)',
                lineHeight: '1.6', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              }}>
                {JSON.stringify(result.url_site_preview, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    );
  }

  return null;
}
