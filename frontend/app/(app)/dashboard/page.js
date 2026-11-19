'use client'
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { api } from '../../lib/api'

export default function DashboardPage() {
  const router  = useRouter()
  const [user,    setUser]    = useState(null)
  const [history, setHistory] = useState([])
  const [summary, setSummary] = useState({
    total_scans: 0,
    threats_detected: 0,
    benign_scans: 0,
    average_confidence: 0,
    severity_breakdown: { Critical: 0, High: 0, Medium: 0, Low: 0 },
    by_scan_type: { IDS: 0, Malware: 0 },
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const u = localStorage.getItem('xai_user')
    if (u) setUser(JSON.parse(u))
    fetchHistory()
    fetchSummary()
  }, [])

  async function fetchHistory() {
    try {
      const data = await api.history()
      setHistory(data)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  async function fetchSummary() {
    try {
      const data = await api.historySummary()
      setSummary(data)
    } catch {
      // ignore
    }
  }

  const threats = history.filter(h =>
    h.result.toLowerCase().includes('attack') ||
    h.result.toLowerCase() === 'malware'
  ).length

  const idScans      = history.filter(h => h.scan_type === 'IDS').length
  const malwareScans = history.filter(h => h.scan_type === 'Malware').length

  const threatRate = summary.total_scans ? ((summary.threats_detected / summary.total_scans) * 100).toFixed(0) : '0'

  return (
    <>
      {/* Page Header */}
      <div className="page-header">
        <h1>📊 SOC Dashboard</h1>
        <p>Welcome back, <strong style={{ color: 'var(--accent)' }}>{user?.username || 'Analyst'}</strong> · Real-time threat monitoring</p>
      </div>

      {/* Metrics */}
      <div className="metrics-grid mb-6">
        <div className="metric-card">
          <span className="metric-icon">🗃️</span>
          <div className="metric-label">Total Scans</div>
          <div className="metric-value accent">{summary.total_scans || history.length}</div>
        </div>
        <div className="metric-card danger">
          <span className="metric-icon">⚠️</span>
          <div className="metric-label">Threats Detected</div>
          <div className="metric-value danger">{summary.threats_detected || threats}</div>
        </div>
        <div className="metric-card success">
          <span className="metric-icon">📈</span>
          <div className="metric-label">Threat Rate</div>
          <div className="metric-value success">{threatRate}%</div>
        </div>
        <div className="metric-card purple">
          <span className="metric-icon">🎯</span>
          <div className="metric-label">Avg Confidence</div>
          <div className="metric-value" style={{ color: 'var(--purple)' }}>
            {((summary.average_confidence || 0) * 100).toFixed(1)}%
          </div>
        </div>
      </div>

      <div className="card mb-6">
        <div className="section-title">🛡️ Security Posture Summary</div>
        <div className="grid-3">
          <div className="metric-card">
            <div className="metric-label">Benign Scans</div>
            <div className="metric-value success">{summary.benign_scans || (history.length - threats)}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Critical / High</div>
            <div className="metric-value danger">{(summary.severity_breakdown?.Critical || 0) + (summary.severity_breakdown?.High || 0)}</div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Malware Scans</div>
            <div className="metric-value warning">{summary.by_scan_type?.Malware || malwareScans}</div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="section-title">⚡ Quick Actions</div>
      <div className="quick-actions mb-8">
        <div className="quick-action-card" onClick={() => router.push('/ids')}>
          <div className="quick-action-icon">🔍</div>
          <div className="quick-action-title">IDS Scanner</div>
          <div className="quick-action-sub">Analyze network traffic</div>
        </div>
        <div className="quick-action-card" onClick={() => router.push('/malware')}>
          <div className="quick-action-icon">🦠</div>
          <div className="quick-action-title">Malware Scanner</div>
          <div className="quick-action-sub">Scan executables &amp; files</div>
        </div>
        <div className="quick-action-card" onClick={() => router.push('/history')}>
          <div className="quick-action-icon">📋</div>
          <div className="quick-action-title">Scan History</div>
          <div className="quick-action-sub">View all past scans</div>
        </div>
        <div className="quick-action-card" onClick={() => router.push('/insights')}>
          <div className="quick-action-icon">🤖</div>
          <div className="quick-action-title">Model Insights</div>
          <div className="quick-action-sub">Performance &amp; accuracy</div>
        </div>
      </div>

      {/* Threat Level Summary */}
      <div className="grid-2 mb-6">
        <div className="card">
          <div className="section-title">🛡️ Threat Level Breakdown</div>
          {history.length === 0 ? (
            <p className="text-muted text-sm" style={{ padding: '16px 0' }}>No scans yet — run your first scan to see data.</p>
          ) : (
            (() => {
              const counts = {}
              history.forEach(h => { counts[h.result] = (counts[h.result] || 0) + 1 })
              return Object.entries(counts).slice(0, 6).map(([label, count]) => (
                <div key={label} style={{ marginBottom: 12 }}>
                  <div className="flex justify-between mb-2" style={{ fontSize: 13 }}>
                    <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{count}</span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className={`progress-fill ${label.toLowerCase().includes('normal') || label === 'Benign' ? 'success' : 'danger'}`}
                      style={{ width: `${Math.round((count / history.length) * 100)}%` }}
                    />
                  </div>
                </div>
              ))
            })()
          )}
        </div>

        <div className="card">
          <div className="section-title">📅 Recent Activity</div>
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: '24px' }}>
              <div className="spinner" />
            </div>
          ) : history.length === 0 ? (
            <p className="text-muted text-sm" style={{ padding: '16px 0' }}>No recent scans.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {history.slice(0, 5).map((h, i) => (
                <div key={i} className="flex justify-between items-center" style={{
                  padding: '10px 14px',
                  background: 'var(--bg-surface)',
                  borderRadius: 8,
                  fontSize: 13,
                }}>
                  <div>
                    <span style={{ marginRight: 8 }}>{h.scan_type === 'IDS' ? '🔍' : '🦠'}</span>
                    <strong>{h.result}</strong>
                  </div>
                  <div className="flex gap-2 items-center">
                    <span className={`badge ${h.result.toLowerCase().includes('normal') || h.result === 'Benign' ? 'badge-success' : 'badge-danger'}`}>
                      {(h.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* System Info */}
      <div className="card card-sm">
        <div className="flex items-center gap-3">
          <span className="status-dot" />
          <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            XAI-Sec v2.0 · FastAPI Backend · Next.js Frontend · SHAP/LIME Explainability · SQLite Storage
          </span>
        </div>
      </div>
    </>
  )
}
