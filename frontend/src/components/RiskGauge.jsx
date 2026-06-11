import React from 'react';

/**
 * Animated SVG risk gauge (semicircular arc, 0-100).
 */
export default function RiskGauge({ score, classification, compact = false }) {
  const radius = compact ? 50 : 80;
  const stroke = compact ? 8 : 12;
  const cx = compact ? 70 : 110;
  const cy = compact ? 70 : 120;
  const startAngle = Math.PI;
  const endAngle = 0;
  const totalArc = Math.PI;

  // Score arc
  const scoreAngle = startAngle - (score / 100) * totalArc;
  const arcX1 = cx + radius * Math.cos(startAngle);
  const arcY1 = cy - radius * Math.sin(startAngle);
  const arcX2 = cx + radius * Math.cos(scoreAngle);
  const arcY2 = cy - radius * Math.sin(scoreAngle);
  const largeArc = score > 50 ? 1 : 0;

  // Background arc (full semicircle)
  const bgX1 = cx + radius * Math.cos(startAngle);
  const bgY1 = cy - radius * Math.sin(startAngle);
  const bgX2 = cx + radius * Math.cos(endAngle);
  const bgY2 = cy - radius * Math.sin(endAngle);

  const colorMap = {
    LOW: 'var(--risk-low)',
    MEDIUM: 'var(--risk-medium)',
    HIGH: 'var(--risk-high)',
    CRITICAL: 'var(--risk-critical)',
  };
  const color = colorMap[classification] || 'var(--cyan)';

  const classLabel = {
    LOW: '🟢',
    MEDIUM: '🟡',
    HIGH: '🔴',
    CRITICAL: '⚠️',
  };

  return (
    <div className="risk-gauge" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: compact ? '2px 0' : '8px 0' }}>
      <svg className="risk-gauge__svg" viewBox={compact ? "0 0 140 90" : "0 0 220 140"} style={{ width: compact ? '80px' : '120px', height: compact ? '55px' : '85px', display: 'block' }}>
        {/* Background arc */}
        <path
          d={`M ${bgX1} ${bgY1} A ${radius} ${radius} 0 0 1 ${bgX2} ${bgY2}`}
          fill="none"
          stroke="rgba(148, 163, 184, 0.08)"
          strokeWidth={stroke}
          strokeLinecap="round"
        />
        {/* Score arc */}
        {score > 0 && (
          <path
            d={`M ${arcX1} ${arcY1} A ${radius} ${radius} 0 0 1 ${arcX2} ${arcY2}`}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 6px ${color})`,
              transition: 'all 0.8s ease',
            }}
          />
        )}
      </svg>
      <div className="risk-gauge__score" style={{ color, fontSize: compact ? '18px' : '24px', fontWeight: '800', marginTop: compact ? '-22px' : '-32px', lineBaseline: 'middle' }}>
        {Math.round(score)}
      </div>
      {!compact && (
        <div className="risk-gauge__label" style={{ color, fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', marginTop: '6px' }}>
          {classLabel[classification]} {classification}
        </div>
      )}
    </div>
  );
}
