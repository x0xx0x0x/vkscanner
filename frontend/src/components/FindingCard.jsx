import React, { useState } from 'react';

/**
 * Severity-colored finding card with evidence display.
 */
export default function FindingCard({ finding }) {
  const [showEvidence, setShowEvidence] = useState(false);

  const severityEmoji = {
    info: 'ℹ️',
    low: '🟢',
    medium: '🟡',
    high: '🔴',
    critical: '⚠️',
  };

  const isMalicious = finding.severity === 'high' || finding.severity === 'critical';

  return (
    <div className={`finding-card finding-card--${finding.severity}`}>
      <div className="finding-card__header">
        <span className="finding-card__title">
          {severityEmoji[finding.severity] || '•'} {finding.title}
        </span>
        <span className="finding-card__impact">
          {finding.score_impact > 0 ? `+${finding.score_impact.toFixed(1)} pts` : ''}
        </span>
      </div>
      <div className="finding-card__desc">{finding.description}</div>
      <div style={{ display: 'flex', gap: '8px', marginTop: '6px', alignItems: 'center' }}>
        <span className={`badge badge--${finding.severity}`}>
          {finding.severity.toUpperCase()}
        </span>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
          {finding.category}
        </span>
        {finding.evidence && (
          <button 
            onClick={() => setShowEvidence(!showEvidence)}
            style={{
              background: isMalicious ? 'rgba(239, 68, 68, 0.1)' : 'rgba(255,255,255,0.05)',
              border: `1px solid ${isMalicious ? 'rgba(239, 68, 68, 0.3)' : 'var(--border-subtle)'}`,
              color: isMalicious ? 'var(--risk-high)' : 'var(--text-secondary)',
              borderRadius: '4px',
              padding: '2px 8px',
              fontSize: '10px',
              cursor: 'pointer',
              fontWeight: 'bold',
              marginLeft: 'auto'
            }}
          >
            {showEvidence ? '▼ HIDE STRING' : (isMalicious ? '▶ CLICK TO VIEW MALICIOUS STRING' : '▶ SHOW EVIDENCE')}
          </button>
        )}
      </div>
      {finding.evidence && showEvidence && (
        <div className="finding-card__evidence" style={{
          marginTop: '10px',
          background: 'rgba(0,0,0,0.3)',
          borderLeft: `2px solid var(--risk-${finding.severity})`,
          padding: '8px 12px',
          borderRadius: '4px',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          wordBreak: 'break-all',
          color: 'var(--text-secondary)'
        }}>
          <strong style={{ color: 'var(--cyan)' }}>📍 Detected in:</strong>
          <br/>
          {finding.evidence}
        </div>
      )}
    </div>
  );
}
