import React, { useState } from 'react';

/**
 * Expandable debug trace panel with premium terminal-style rendering.
 * Features blinking prompt cursor, status headers, and forensic logs.
 */
export default function DebugPanel({ debugTrace, t }) {
  const [open, setOpen] = useState(false);

  if (!debugTrace || debugTrace.length === 0) return null;

  const formatTime = (iso) => {
    try {
      const d = new Date(iso);
      return d.toISOString().substr(11, 12);
    } catch {
      return iso;
    }
  };

  const getResultClass = (step) => {
    const r = (step.result || '').toLowerCase();
    if (r.includes('fail') || r.includes('danger') || r.includes('critical') || r.includes('triggered'))
      return 'debug-step__result--danger';
    if (r.includes('warning') || r.includes('softfail') || r.includes('uncertain'))
      return 'debug-step__result--warning';
    return '';
  };

  const getAnalyzerColor = (analyzer) => {
    const a = (analyzer || '').toLowerCase();
    if (a.includes('olevba') || a.includes('rtfobj')) return '#c084fc'; // Purple/violet
    if (a.includes('bruteforce')) return '#38bdf8'; // Cyan
    if (a.includes('orchestrator')) return '#f43f5e'; // Rose
    if (a.includes('document')) return '#fbbf24'; // Amber
    return 'var(--cyan)';
  };

  const isEs = t?.scan_button === 'Escanear';

  return (
    <div className="debug-panel">
      {/* Self-contained terminal blink animation */}
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes terminal-blink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0; }
        }
        .debug-panel__blink {
          animation: terminal-blink 1s step-end infinite;
        }
      `}} />

      <button
        className="debug-panel__toggle"
        onClick={() => setOpen(!open)}
        id="debug-toggle"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          background: 'var(--bg-secondary)',
          borderBottom: open ? '1px solid var(--border-primary)' : 'none',
          padding: '14px 20px',
        }}
      >
        <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          💻 {open ? (t?.debug_hide || 'Hide Console debug') : (t?.debug_show || 'Show Console / Debug Log')}
          <span style={{
            fontSize: '11px',
            padding: '2px 6px',
            borderRadius: '4px',
            background: 'rgba(56, 189, 248, 0.1)',
            color: 'var(--cyan)',
            border: '1px solid var(--border-primary)',
            fontWeight: 500,
            textTransform: 'uppercase'
          }}>
            {open ? 'ACTIVE' : 'IDLE'}
          </span>
        </span>
        <span className={`debug-panel__toggle-arrow ${open ? 'debug-panel__toggle-arrow--open' : ''}`}>
          ▼
        </span>
      </button>

      <div className={`debug-panel__content ${open ? 'debug-panel__content--open' : ''}`}>
        <div className="debug-panel__terminal" style={{ background: '#020617', borderTop: 'none' }}>
          {/* Terminal Banner */}
          <div style={{
            color: '#38bdf8',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            lineHeight: 1.5,
            marginBottom: '16px',
            paddingBottom: '8px',
            borderBottom: '1px dashed rgba(56, 189, 248, 0.2)'
          }}>
            <div>VK SCANNER FORENSIC DEBUG CONSOLE v2.5.0 (SECURE ENCLAVE)</div>
            <div>[SYS_STATUS] OFFLINE PIPELINES READY · MEMORY FORENSICS ACTIVATED</div>
            <div>[WORKERS] olevba, rtfobj, pikepdf, bruteforce, cv2-quishing initialized.</div>
          </div>

          {/* Trace Steps */}
          {debugTrace.map((step, i) => (
            <div key={i} className="debug-step" style={{ padding: '4px 0' }}>
              <span className="debug-step__time">{formatTime(step.timestamp)}</span>
              <span className="debug-step__analyzer" style={{ color: getAnalyzerColor(step.analyzer) }}>
                [{step.analyzer}]
              </span>
              <span>
                <span className="debug-step__action">{step.action}</span>
                {step.detail && (
                  <span className="debug-step__detail" style={{ color: 'var(--text-secondary)' }}> — {step.detail}</span>
                )}
                {step.result && (
                  <span className={`debug-step__result ${getResultClass(step)}`}>
                    {' → '}{step.result}
                  </span>
                )}
                {step.score_impact > 0 && (
                  <span className="debug-step__impact"> [+{step.score_impact}]</span>
                )}
              </span>
            </div>
          ))}

          {/* Hacker blinking prompt at bottom */}
          <div className="debug-step" style={{ borderBottom: 'none', padding: '6px 0 2px 0', marginTop: '4px' }}>
            <span className="debug-step__time" style={{ color: 'var(--text-muted)' }}>
              [{new Date().toISOString().substr(11, 12)}]
            </span>
            <span className="debug-step__analyzer" style={{ color: 'var(--violet)' }}>[enclave]</span>
            <span style={{ color: 'var(--cyan)' }}>
              vkscanner@forensics-sandbox:~$ <span className="debug-panel__blink" style={{ color: 'var(--cyan)', fontWeight: 'bold' }}>█</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
