'use client'
import { useEffect, useState } from 'react'
import { api } from '../../lib/api'

export default function HistoryPage() {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter,  setFilter]  = useState('all')

  useEffect(() => { fetchHistory() }, [])

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

  const filtered = filter === 'all'
    ? history
    : history.filter(h => h.scan_type.toLowerCase() === filter)

  const threats  = history.filter(h => !['normal traffic', 'benign'].some(s => h.result.toLowerCase().includes(s))).length
  const benign   = history.length - threats
  const avgConf  = history.length ? (history.reduce((s, h) => s + h.confidence, 0) / history.length * 100).toFixed(1) : '—'

  function exportCSV() {
    if (!history.length) return

    const header = ['scan_type', 'result', 'confidence', 'severity', 'timestamp']
    const rows = history.map(h => [
      h.scan_type,
      h.result,
      String(h.confidence),
      h.severity || 'Low',
      h.timestamp,
    ])

    const csv = [header, ...rows].map(row => row.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'xai_sec_scan_history.csv'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <div className="page-header">
        <h1>📋 Scan History</h1>
        <p>Complete audit trail of all past scans</p>
        <button className="btn btn-primary" onClick={exportCSV} disabled={!history.length} style={{ marginTop: 12 }}>
          ⬇️ Export CSV
        </button>
      </div>

      {/* Stats */}
      <div className="metrics-grid mb-6">
        <div className="metric-card">
          <span className="metric-icon">🗃️</span>
          <div className="metric-label">Total Scans</div>
          <div className="metric-value accent">{history.length}</div>
        </div>
        <div className="metric-card danger">
          <span className="metric-icon">🚨</span>
          <div className="metric-label">Threats</div>
          <div className="metric-value danger">{threats}</div>
        </div>
        <div className="metric-card success">
          <span className="metric-icon">✅</span>
          <div className="metric-label">Benign</div>
          <div className="metric-value success">{benign}</div>
        </div>
        <div className="metric-card purple">
          <span className="metric-icon">📊</span>
          <div className="metric-label">Avg Confidence</div>
          <div className="metric-value" style={{ color: 'var(--purple)' }}>{avgConf}%</div>
        </div>
      </div>

      {/* Filter */}
      <div className="tabs">
        {[['all', '🗃️ All'], ['ids', '🔍 IDS'], ['malware', '🦠 Malware']].map(([k, label]) => (
          <button key={k} className={`tab-btn ${filter === k ? 'active' : ''}`} onClick={() => setFilter(k)}>{label}</button>
        ))}
      </div>

      {loading ? (
        <div className="card scan-overlay">
          <div className="spinner" />
          <p>Loading history...</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
          📭 No scan history yet. Run a scan to get started!
        </div>
      ) : (
        <div className="table-wrapper animate-fade-in">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Type</th>
                <th>Result</th>
                <th>Threat Level</th>
                <th>Confidence</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((h, i) => {
                const isThreat = !['normal traffic', 'benign'].some(s => h.result.toLowerCase().includes(s))
                return (
                  <tr key={i}>
                    <td className="text-muted font-mono">{filtered.length - i}</td>
                    <td>
                      <span className="badge badge-accent">
                        {h.scan_type === 'IDS' ? '🔍' : '🦠'} {h.scan_type}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600 }}>{h.result}</td>
                    <td>
                      <span className={`badge ${isThreat ? 'badge-danger' : 'badge-success'}`}>
                        {isThreat ? '🔴 Threat' : '🟢 Benign'}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="progress-bar" style={{ width: 80 }}>
                          <div className={`progress-fill ${isThreat ? 'danger' : 'success'}`} style={{ width: `${h.confidence * 100}%` }} />
                        </div>
                        <span className="font-mono text-sm">{(h.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="text-muted font-mono" style={{ fontSize: 12 }}>{h.timestamp}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
