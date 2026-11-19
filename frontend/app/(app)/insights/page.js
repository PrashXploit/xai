'use client'
// ============================================================
//  XAI-Sec — Model Insights Page  (v2.0)
//  Stack: Next.js App Router · React 19 · Pure CSS (globals.css)
//  Charts: Canvas-drawn Confusion Matrix · CSS SHAP bars
//
//  TO CONNECT TO YOUR REAL BACKEND:
//  1. Remove the `MOCK_DATA` block below.
//  2. In `loadData()`, uncomment the two `api.*` calls.
//  3. Map the API response fields to the same shape as MOCK_DATA.
//     The backend should return GET /api/model-insights → { ids, malware }
//     with the same keys used in MOCK_DATA.ids / MOCK_DATA.malware.
// ============================================================

import { useEffect, useRef, useState, useCallback } from 'react'
import { api } from '../../lib/api'

// ─────────────────────────────────────────────────────────────
//  MOCK DATA — swap this for your real API response
// ─────────────────────────────────────────────────────────────
const MOCK_DATA = {
  ids: {
    // Overall KPIs (0–1 floats)
    metrics: { accuracy: 0.9731, precision: 0.9684, recall: 0.9712, f1_score: 0.9698 },

    // Per-class F1 (label → 0–1)
    per_class_f1: {
      Normal:   0.989,
      DoS:      0.961,
      Probe:    0.954,
      R2L:      0.942,
      U2R:      0.933,
    },

    // Confusion matrix rows = actual, cols = predicted
    // Order matches class_labels
    class_labels: ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
    confusion_matrix: [
      [9820,  40,  18,  10,  12],
      [  28, 952,  11,   5,   4],
      [  15,   8, 874,   6,   3],
      [  12,   4,   5, 621,   8],
      [   9,   3,   4,   6, 198],
    ],

    // Top SHAP global importances (feature → mean |SHAP|)
    shap_importances: [
      { feature: 'dst_bytes',           value: 0.3821 },
      { feature: 'src_bytes',           value: 0.3104 },
      { feature: 'duration',            value: 0.2487 },
      { feature: 'count',               value: 0.1953 },
      { feature: 'serror_rate',         value: 0.1762 },
      { feature: 'srv_count',           value: 0.1548 },
      { feature: 'same_srv_rate',       value: 0.1301 },
      { feature: 'diff_srv_rate',       value: 0.1189 },
      { feature: 'dst_host_count',      value: 0.0974 },
      { feature: 'flag',                value: 0.0812 },
    ],

    // Architecture metadata
    arch: {
      algorithm:    'Random Forest',
      n_estimators: 200,
      dataset:      'NSL-KDD',
      train_split:  '80 / 20',
      last_trained: '2025-11-01',
      xai_engine:   'SHAP TreeExplainer',
      pipeline:     'Sklearn Pipeline',
      classes:      5,
    },
  },

  malware: {
    metrics: { accuracy: 0.9876, precision: 0.9841, recall: 0.9863, f1_score: 0.9852 },

    per_class_f1: {
      Benign:  0.991,
      Malware: 0.979,
    },

    class_labels: ['Benign', 'Malware'],
    confusion_matrix: [
      [4921,  39],
      [  22, 918],
    ],

    shap_importances: [
      { feature: 'NumberOfImports',      value: 0.4512 },
      { feature: 'SectionsMaxEntropy',   value: 0.3876 },
      { feature: 'SectionsMeanEntropy',  value: 0.3241 },
      { feature: 'NumberOfExports',      value: 0.2934 },
      { feature: 'ResourcesMeanEntropy', value: 0.2187 },
      { feature: 'DllCharacteristics',   value: 0.1954 },
      { feature: 'DirectoryEntropies',   value: 0.1763 },
      { feature: 'e_minalloc',           value: 0.1512 },
      { feature: 'MajorLinkerVersion',   value: 0.1234 },
      { feature: 'SizePeHeader',         value: 0.1021 },
    ],

    arch: {
      algorithm:    'Random Forest',
      n_estimators: 150,
      dataset:      'EMBER / BODMAS',
      train_split:  '80 / 20',
      last_trained: '2025-11-01',
      xai_engine:   'SHAP TreeExplainer',
      pipeline:     'Sklearn Pipeline',
      classes:      2,
    },
  },
}

// ─────────────────────────────────────────────────────────────
//  Lucide-style SVG icon set (inline, no external dep)
// ─────────────────────────────────────────────────────────────
const Icon = {
  Cpu: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/>
      <line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/>
      <line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/>
      <line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/>
      <line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>
    </svg>
  ),
  Shield: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Bug: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4"/><path d="M20 12h2M2 12h2M12 2v2M12 20v2"/>
      <path d="m4.93 4.93 1.41 1.41M17.66 17.66l1.41 1.41M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>
    </svg>
  ),
  BarChart2: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/>
      <line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/>
    </svg>
  ),
  GitBranch: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/>
      <path d="M18 9a9 9 0 0 1-9 9"/>
    </svg>
  ),
  Layers: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>
    </svg>
  ),
  Zap: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
    </svg>
  ),
  RefreshCw: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
    </svg>
  ),
  ArrowRight: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
    </svg>
  ),
  Info: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
    </svg>
  ),
  Compare: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="9" height="18" rx="1"/><rect x="13" y="3" width="9" height="18" rx="1"/>
    </svg>
  ),
}

// ─────────────────────────────────────────────────────────────
//  Skeleton Shimmer Placeholder
// ─────────────────────────────────────────────────────────────
function Skeleton({ width = '100%', height = 20, style = {} }) {
  return (
    <div
      className="skeleton"
      style={{ width, height, borderRadius: 8, ...style }}
    />
  )
}

function ModelCardSkeleton() {
  return (
    <div className="card animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <Skeleton width={32} height={32} style={{ borderRadius: '50%' }} />
        <Skeleton width={160} height={22} />
        <Skeleton width={70} height={22} style={{ marginLeft: 'auto', borderRadius: 99 }} />
      </div>
      {/* KPI tiles */}
      <div className="insights-kpi-grid mb-6">
        {[1,2,3,4].map(i => (
          <div key={i} className="metric-card" style={{ padding: 20 }}>
            <Skeleton width={60} height={11} style={{ marginBottom: 12 }} />
            <Skeleton width={90} height={34} />
            <Skeleton width={50} height={10} style={{ marginTop: 10 }} />
          </div>
        ))}
      </div>
      {/* Chart placeholders */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Skeleton height={220} />
        <Skeleton height={220} />
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Error State
// ─────────────────────────────────────────────────────────────
function ErrorCard({ message, onRetry }) {
  return (
    <div className="card animate-fade-in" style={{ textAlign: 'center', padding: '48px 32px' }}>
      <div style={{ fontSize: 40, marginBottom: 16, opacity: 0.6 }}>⚠️</div>
      <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--danger)', marginBottom: 8 }}>
        Failed to load model data
      </div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 24 }}>
        {message || 'An unexpected error occurred. Please try again.'}
      </div>
      <button className="btn btn-primary" onClick={onRetry} style={{ margin: '0 auto' }}>
        <Icon.RefreshCw /> Retry
      </button>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  KPI Tile
// ─────────────────────────────────────────────────────────────
const KPI_CONFIG = [
  { key: 'accuracy',  label: 'Accuracy',  color: 'accent',   sub: 'Overall correct predictions' },
  { key: 'precision', label: 'Precision', color: 'cyan',     sub: 'TP / (TP + FP)' },
  { key: 'recall',    label: 'Recall',    color: 'success',  sub: 'TP / (TP + FN)' },
  { key: 'f1_score',  label: 'F1 Score',  color: 'warning',  sub: 'Harmonic mean P/R' },
]

function KpiTile({ label, value, color, sub }) {
  const pct = (value * 100).toFixed(2) + '%'
  return (
    <div className={`metric-card ${color} insights-kpi-tile`}>
      <div className="metric-label">{label}</div>
      <div className={`metric-value ${color}`}>{pct}</div>
      <div className="metric-sub">{sub}</div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Confusion Matrix — Canvas heatmap
// ─────────────────────────────────────────────────────────────
function ConfusionMatrix({ matrix, labels }) {
  const canvasRef = useRef(null)

  useEffect(() => {
    if (!canvasRef.current || !matrix?.length) return
    const canvas = canvasRef.current
    const ctx    = canvas.getContext('2d')
    const n      = matrix.length
    const dpr    = window.devicePixelRatio || 1

    const LABEL_W  = 70
    const LABEL_H  = 70
    const CELL     = 68
    const PAD      = 12

    const W = LABEL_W + n * CELL + PAD
    const H = LABEL_H + n * CELL + PAD
    canvas.width  = W * dpr
    canvas.height = H * dpr
    canvas.style.width  = W + 'px'
    canvas.style.height = H + 'px'
    ctx.scale(dpr, dpr)

    ctx.clearRect(0, 0, W, H)

    // Find max for normalising colour
    const flat = matrix.flat()
    const maxV = Math.max(...flat)

    // Colour ramp: dark navy → bright indigo
    function cellColor(val) {
      const t = val / maxV
      // Interpolate between #0f172a (dark) and #6366f1 (indigo), highlight diagonal
      const r = Math.round(15  + t * (99  - 15))
      const g = Math.round(23  + t * (102 - 23))
      const b = Math.round(42  + t * (241 - 42))
      return `rgb(${r},${g},${b})`
    }

    // Draw cells
    for (let row = 0; row < n; row++) {
      for (let col = 0; col < n; col++) {
        const x = LABEL_W + col * CELL
        const y = LABEL_H + row * CELL
        const v = matrix[row][col]

        ctx.fillStyle = cellColor(v)
        ctx.fillRect(x, y, CELL - 2, CELL - 2)

        // Diagonal highlight ring
        if (row === col) {
          ctx.strokeStyle = 'rgba(99,102,241,0.9)'
          ctx.lineWidth   = 2
          ctx.strokeRect(x + 1, y + 1, CELL - 4, CELL - 4)
        }

        // Count text
        const brightness = v / maxV
        ctx.fillStyle = brightness > 0.45 ? '#f1f5f9' : '#94a3b8'
        ctx.font      = `600 ${v >= 1000 ? 11 : 13}px Inter, sans-serif`
        ctx.textAlign    = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText(v.toLocaleString(), x + CELL / 2 - 1, y + CELL / 2 - 1)
      }
    }

    // X-axis labels (Predicted)
    ctx.fillStyle = 'rgba(148,163,184,0.9)'
    ctx.font = '500 11px Inter, sans-serif'
    ctx.textAlign = 'center'
    for (let col = 0; col < n; col++) {
      const x = LABEL_W + col * CELL + CELL / 2 - 1
      ctx.fillText(labels[col], x, LABEL_H - 10)
    }

    // Y-axis labels (Actual) — rotated
    ctx.save()
    ctx.translate(LABEL_W - 10, LABEL_H)
    ctx.textAlign = 'right'
    for (let row = 0; row < n; row++) {
      ctx.fillText(labels[row], 0, row * CELL + CELL / 2 - 1)
    }
    ctx.restore()

    // Axis titles
    ctx.fillStyle = 'rgba(99,102,241,0.8)'
    ctx.font = '600 11px Inter, sans-serif'
    ctx.textAlign = 'center'
    ctx.fillText('Predicted →', LABEL_W + (n * CELL) / 2, 14)

    ctx.save()
    ctx.translate(10, LABEL_H + (n * CELL) / 2)
    ctx.rotate(-Math.PI / 2)
    ctx.textAlign = 'center'
    ctx.fillText('← Actual', 0, 0)
    ctx.restore()
  }, [matrix, labels])

  return (
    <div>
      <div className="insights-section-label">
        <Icon.BarChart2 /> Confusion Matrix
      </div>
      <div style={{ overflowX: 'auto' }}>
        <canvas ref={canvasRef} style={{ display: 'block', margin: '0 auto', borderRadius: 8 }} />
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Per-class F1 Bar Chart (pure CSS)
// ─────────────────────────────────────────────────────────────
function PerClassF1({ data, type }) {
  const entries = Object.entries(data)
  const isIds   = type === 'ids'

  function barColor(label) {
    const l = label.toLowerCase()
    if (l === 'normal' || l === 'benign') return 'var(--success)'
    if (l === 'malware') return 'var(--danger)'
    // Attack subtypes → gradient of indigo/cyan/warning
    const idx = entries.findIndex(([k]) => k === label)
    const cols = ['var(--danger)', 'var(--warning)', '#f97316', '#a855f7']
    return cols[(idx - 1) % cols.length] || 'var(--accent-light)'
  }

  return (
    <div>
      <div className="insights-section-label">
        <Icon.BarChart2 /> Per-class F1 Score
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {entries.map(([label, f1]) => (
          <div key={label}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>
                {label}
              </span>
              <span style={{ fontSize: 12, fontWeight: 700, color: barColor(label) }}>
                {(f1 * 100).toFixed(1)}%
              </span>
            </div>
            <div className="progress-bar" style={{ height: 8 }}>
              <div
                className="progress-fill"
                style={{
                  width: `${f1 * 100}%`,
                  background: barColor(label),
                  transition: 'width 0.8s cubic-bezier(0.4,0,0.2,1)',
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  SHAP Feature Importance (enhanced horizontal bars)
// ─────────────────────────────────────────────────────────────
function ShapImportance({ importances, type }) {
  const sorted  = [...importances].sort((a, b) => b.value - a.value).slice(0, 10)
  const maxVal  = sorted[0]?.value || 1
  const caption = type === 'ids'
    ? 'Features pushing predictions toward Attack class'
    : 'Features pushing predictions toward Malware class'

  return (
    <div className="card">
      <div className="insights-section-label" style={{ marginBottom: 6 }}>
        <Icon.Zap /> Top SHAP Feature Importances
      </div>
      <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 18, fontStyle: 'italic' }}>
        {caption}
      </p>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 16, fontSize: 11.5 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--accent-light)', display: 'inline-block' }} />
          Mean |SHAP| value
        </span>
      </div>

      {sorted.map((item, i) => {
        const pct = (item.value / maxVal) * 100
        const rank = i + 1
        return (
          <div key={item.feature} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
            {/* Rank */}
            <span style={{
              fontSize: 10, fontWeight: 700, color: rank <= 3 ? 'var(--accent-light)' : 'var(--text-dim)',
              width: 18, textAlign: 'right', flexShrink: 0,
            }}>
              #{rank}
            </span>
            {/* Feature name */}
            <span className="font-mono" style={{
              fontSize: 11.5, color: 'var(--text-secondary)',
              width: 190, flexShrink: 0,
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              background: 'none', padding: 0,
            }} title={item.feature}>
              {item.feature}
            </span>
            {/* Bar */}
            <div style={{
              flex: 1, height: 20, background: 'var(--bg-surface)',
              borderRadius: 4, overflow: 'hidden', position: 'relative',
            }}>
              <div style={{
                width: `${pct}%`,
                height: '100%',
                background: i < 3
                  ? 'linear-gradient(90deg, var(--accent-dim), var(--accent-light))'
                  : 'linear-gradient(90deg, #2d3f7a, var(--accent))',
                borderRadius: 4,
                transition: 'width 0.7s cubic-bezier(0.4,0,0.2,1)',
              }} />
            </div>
            {/* Value */}
            <span className="font-mono" style={{
              fontSize: 11, color: 'var(--text-muted)', width: 56,
              textAlign: 'right', flexShrink: 0, background: 'none', padding: 0,
            }}>
              {item.value.toFixed(4)}
            </span>
          </div>
        )
      })}

      {/* SHAP image slot */}
      <div style={{
        marginTop: 20,
        border: '1.5px dashed var(--border)',
        borderRadius: 10,
        padding: '20px',
        textAlign: 'center',
        background: 'rgba(99,102,241,0.02)',
      }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>
          <Icon.Info /> SHAP Summary Plot
        </div>
        <p style={{ fontSize: 11.5, color: 'var(--text-dim)', fontStyle: 'italic' }}>
          Slot for real SHAP beeswarm plot (PNG/SVG from backend).<br/>
          Replace with: &lt;img src=&#123;`data:image/png;base64,&#36;&#123;data.shap_plot&#125;`&#125; /&gt;
        </p>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Pipeline Architecture visualizer
// ─────────────────────────────────────────────────────────────
const PIPELINE_STEPS = [
  { key: 'raw',      label: 'Raw Data',          icon: <Icon.Layers />,    color: 'var(--text-muted)' },
  { key: 'pipeline', label: 'Sklearn Pipeline',   icon: <Icon.GitBranch />, color: 'var(--cyan)' },
  { key: 'rf',       label: 'Random Forest',      icon: <Icon.Cpu />,       color: 'var(--accent-light)' },
  { key: 'shap',     label: 'SHAP Explainer',     icon: <Icon.Zap />,       color: 'var(--warning)' },
  { key: 'verdict',  label: 'Verdict',            icon: <Icon.Shield />,    color: 'var(--success)' },
]

function ArchPipeline({ arch, modelLabel }) {
  const chips = [
    { label: 'Trees',         value: arch.n_estimators },
    { label: 'Dataset',       value: arch.dataset },
    { label: 'Train / Test',  value: arch.train_split },
    { label: 'Last Trained',  value: arch.last_trained },
    { label: 'Classes',       value: arch.classes },
    { label: 'XAI Engine',    value: arch.xai_engine },
  ]

  return (
    <div>
      {/* Flow diagram */}
      <div className="insights-pipeline-flow">
        {PIPELINE_STEPS.map((step, i) => (
          <div key={step.key} style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
            <div className="insights-pipeline-node" style={{ '--node-color': step.color }}>
              <span style={{ color: step.color, display: 'flex', alignItems: 'center' }}>
                {step.icon}
              </span>
              <span className="insights-pipeline-label">{step.label}</span>
            </div>
            {i < PIPELINE_STEPS.length - 1 && (
              <div className="insights-pipeline-arrow">
                <Icon.ArrowRight />
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Detail chips */}
      <div className="insights-chips-row">
        {chips.map(c => (
          <div key={c.label} className="insights-chip">
            <span className="insights-chip-label">{c.label}</span>
            <span className="insights-chip-value">{c.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Compare panel: side-by-side KPIs
// ─────────────────────────────────────────────────────────────
function ComparePanel({ idsData, malwareData }) {
  const metrics = ['accuracy', 'precision', 'recall', 'f1_score']
  const labels  = { accuracy: 'Accuracy', precision: 'Precision', recall: 'Recall', f1_score: 'F1 Score' }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header row */}
      <div className="card" style={{ display: 'grid', gridTemplateColumns: '160px 1fr 1fr', gap: 20, alignItems: 'center' }}>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>METRIC</span>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-light)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
            <Icon.Shield /> IDS Model
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>NSL-KDD · 5-class</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--danger)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
            <Icon.Bug /> Malware Classifier
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>EMBER · 2-class</div>
        </div>
      </div>

      {/* Metric comparison rows */}
      {metrics.map(m => {
        const idsVal     = idsData?.metrics?.[m] ?? 0
        const malwareVal = malwareData?.metrics?.[m] ?? 0
        const winner     = idsVal >= malwareVal ? 'ids' : 'malware'
        return (
          <div key={m} className="card" style={{ display: 'grid', gridTemplateColumns: '160px 1fr 1fr', gap: 20, alignItems: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.6px' }}>
              {labels[m]}
            </span>
            {/* IDS */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 20, fontWeight: 800, color: winner === 'ids' ? 'var(--accent-light)' : 'var(--text-secondary)' }}>
                  {(idsVal * 100).toFixed(2)}%
                </span>
                {winner === 'ids' && (
                  <span className="badge badge-accent" style={{ fontSize: 10 }}>BEST</span>
                )}
              </div>
              <div className="progress-bar" style={{ height: 6 }}>
                <div className="progress-fill" style={{ width: `${idsVal * 100}%` }} />
              </div>
            </div>
            {/* Malware */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 20, fontWeight: 800, color: winner === 'malware' ? 'var(--danger)' : 'var(--text-secondary)' }}>
                  {(malwareVal * 100).toFixed(2)}%
                </span>
                {winner === 'malware' && (
                  <span className="badge badge-danger" style={{ fontSize: 10 }}>BEST</span>
                )}
              </div>
              <div className="progress-bar" style={{ height: 6 }}>
                <div className="progress-fill danger" style={{ width: `${malwareVal * 100}%` }} />
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Full Model Tab (IDS or Malware)
// ─────────────────────────────────────────────────────────────
function ModelTab({ data, type }) {
  const isIds  = type === 'ids'
  const accent = isIds ? 'var(--accent-light)' : 'var(--danger)'
  const badge  = isIds ? 'badge-accent' : 'badge-danger'
  const tagTxt = isIds ? '5-class · NSL-KDD' : '2-class · EMBER'
  const icon   = isIds ? <Icon.Shield /> : <Icon.Bug />

  return (
    <div className="animate-slide-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* ── KPI Tiles ─────────────────────────── */}
      <div className="card">
        <div className="flex items-center gap-3 mb-6" style={{ flexWrap: 'wrap' }}>
          <span style={{ color: accent, display: 'flex' }}>{icon}</span>
          <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
            {isIds ? 'IDS Model' : 'Malware Classifier'}
          </span>
          <span className={`badge ${badge}`}>{tagTxt}</span>
          <span className="badge badge-cyan" style={{ marginLeft: 'auto' }}>
            Random Forest
          </span>
        </div>

        <div className="insights-kpi-grid">
          {KPI_CONFIG.map(cfg => (
            <KpiTile key={cfg.key} {...cfg} value={data.metrics[cfg.key]} />
          ))}
        </div>
      </div>

      {/* ── Matrix + Per-class F1 ──────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 24, alignItems: 'start' }}>
        <div className="card" style={{ minWidth: 0 }}>
          <ConfusionMatrix matrix={data.confusion_matrix} labels={data.class_labels} />
        </div>
        <div className="card">
          <PerClassF1 data={data.per_class_f1} type={type} />
        </div>
      </div>

      {/* ── XAI / SHAP ───────────────────────── */}
      <ShapImportance importances={data.shap_importances} type={type} />

      {/* ── Architecture ─────────────────────── */}
      <div className="card">
        <div className="insights-section-label" style={{ marginBottom: 20 }}>
          <Icon.Layers /> Model Architecture Pipeline
        </div>
        <ArchPipeline arch={data.arch} modelLabel={isIds ? 'IDS' : 'Malware'} />
      </div>

    </div>
  )
}

// ─────────────────────────────────────────────────────────────
//  Root Page Component
// ─────────────────────────────────────────────────────────────
export default function InsightsPage() {
  const [activeTab, setActiveTab]  = useState('ids')      // 'ids' | 'malware' | 'compare'
  const [status,    setStatus]     = useState('loading')  // 'loading' | 'ok' | 'error'
  const [error,     setError]      = useState(null)
  const [data,      setData]       = useState({ ids: null, malware: null })

  // ── Data loader ──────────────────────────────────────────
  const loadData = useCallback(async () => {
    setStatus('loading')
    setError(null)
    try {
      // ── MOCK (remove these two lines & uncomment the API calls below) ──
      await new Promise(r => setTimeout(r, 900))          // simulate latency
      const [ids, malware] = [MOCK_DATA.ids, MOCK_DATA.malware]

      // ── REAL BACKEND (uncomment when ready) ───────────────
      // const [ids, malware] = await Promise.all([
      //   api.idsMetrics(),      // GET /models/ids
      //   api.malwareMetrics(),  // GET /models/malware
      // ])

      setData({ ids, malware })
      setStatus('ok')
    } catch (e) {
      setError(e.message || 'Unknown error')
      setStatus('error')
    }
  }, [])

  useEffect(() => { loadData() }, [loadData])

  // ── Tab definitions ───────────────────────────────────────
  const TABS = [
    { id: 'ids',     label: 'IDS Model',          icon: <Icon.Shield /> },
    { id: 'malware', label: 'Malware Classifier',  icon: <Icon.Bug />    },
    { id: 'compare', label: 'Compare',             icon: <Icon.Compare /> },
  ]

  // ─────────────────────────────────────────────────────────
  return (
    <>
      {/* Page header */}
      <div className="page-header">
        <div className="flex items-center gap-3" style={{ flexWrap: 'wrap' }}>
          <div>
            <h1 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: 'var(--accent-light)', display: 'flex' }}><Icon.Cpu /></span>
              Model Insights
            </h1>
            <p>Performance metrics, confusion matrices, SHAP explainability &amp; architecture overview</p>
          </div>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, flexShrink: 0 }}>
            <span className="badge badge-accent">v2.0</span>
            <button
              className="btn btn-ghost"
              onClick={loadData}
              disabled={status === 'loading'}
              style={{ fontSize: 12 }}
            >
              <Icon.RefreshCw />
              {status === 'loading' ? 'Loading…' : 'Refresh'}
            </button>
          </div>
        </div>
      </div>

      {/* Tab switcher */}
      <div className="tabs" style={{ marginBottom: 28 }}>
        {TABS.map(t => (
          <button
            key={t.id}
            className={`tab-btn ${activeTab === t.id ? 'active' : ''}`}
            onClick={() => setActiveTab(t.id)}
            style={{ display: 'flex', alignItems: 'center', gap: 7 }}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* ── Loading ── */}
      {status === 'loading' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <ModelCardSkeleton />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
            <Skeleton height={280} />
            <Skeleton height={280} />
          </div>
        </div>
      )}

      {/* ── Error ── */}
      {status === 'error' && (
        <ErrorCard message={error} onRetry={loadData} />
      )}

      {/* ── Content ── */}
      {status === 'ok' && (
        <>
          {activeTab === 'ids'     && <ModelTab data={data.ids}     type="ids"     />}
          {activeTab === 'malware' && <ModelTab data={data.malware} type="malware" />}
          {activeTab === 'compare' && (
            <div className="animate-slide-up">
              <ComparePanel idsData={data.ids} malwareData={data.malware} />
            </div>
          )}
        </>
      )}
    </>
  )
}
