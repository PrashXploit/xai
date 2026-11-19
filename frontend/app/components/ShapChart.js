'use client'

/**
 * ShapChart — horizontal bar chart for SHAP values.
 * No external charting library needed; pure CSS bars.
 */
export default function ShapChart({ shapValues = [], title = 'Feature Contributions (SHAP)' }) {
  if (!shapValues.length) {
    return (
      <div className="card" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '32px' }}>
        No SHAP data available
      </div>
    )
  }

  // Take top 10 by absolute value
  const sorted = [...shapValues]
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 10)

  const maxAbs = Math.max(...sorted.map(d => Math.abs(d.value)), 0.001)

  return (
    <div className="card animate-fade-in">
      <div className="section-title">{title}</div>

      {/* Legend */}
      <div className="flex gap-4 mb-4" style={{ fontSize: 12 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 12, height: 12, borderRadius: 2, background: '#f87171', display: 'inline-block' }} />
          Increases risk
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 12, height: 12, borderRadius: 2, background: '#60a5fa', display: 'inline-block' }} />
          Reduces risk
        </span>
      </div>

      {sorted.map((item, i) => {
        const pct = (Math.abs(item.value) / maxAbs) * 50 // max 50% of track width
        const isPos = item.value >= 0
        return (
          <div key={i} className="shap-bar">
            <div className="shap-label" title={item.feature}>{item.feature}</div>
            <div className="shap-bar-track">
              {/* Center line */}
              <div style={{
                position: 'absolute', left: '50%', top: 0, width: 1,
                height: '100%', background: 'rgba(255,255,255,0.1)'
              }} />
              <div
                className={`shap-bar-fill ${isPos ? 'positive' : 'negative'}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <div className="shap-value" style={{ color: isPos ? '#f87171' : '#60a5fa' }}>
              {item.value >= 0 ? '+' : ''}{item.value.toFixed(4)}
            </div>
          </div>
        )
      })}
    </div>
  )
}
