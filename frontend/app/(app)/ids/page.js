'use client'
import { useState } from 'react'
import { api } from '../../lib/api'
import ShapChart from '../../components/ShapChart'

export default function IDSPage() {
  const [mode,      setMode]      = useState('sample')  // 'sample' | 'upload'
  const [file,      setFile]      = useState(null)
  const [idx,       setIdx]       = useState(0)
  const [scanning,  setScanning]  = useState(false)
  const [result,    setResult]    = useState(null)
  const [error,     setError]     = useState('')
  const [activeTab, setActiveTab] = useState('shap')

  async function runScan() {
    setError(''); setScanning(true); setResult(null)
    try {
      const data = await api.idsScan(mode === 'upload' ? file : null, idx)
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  return (
    <>
      <div className="page-header">
        <h1>🔍 IDS Scanner</h1>
        <p>Intrusion Detection System — Classify network traffic with AI explainability</p>
      </div>

      {/* Input Mode */}
      <div className="card mb-6">
        <div className="section-title">📥 Input Configuration</div>

        {/* Mode selector */}
        <div className="auth-tabs" style={{ maxWidth: 340, marginBottom: 24 }}>
          <button className={`auth-tab ${mode === 'sample' ? 'active' : ''}`} onClick={() => { setMode('sample'); setFile(null) }}>Generate Sample</button>
          <button className={`auth-tab ${mode === 'upload' ? 'active' : ''}`} onClick={() => setMode('upload')}>Upload CSV</button>
        </div>

        {mode === 'sample' && (
          <div className="alert alert-info">
            📡 Loading real IDS records from the project dataset for live classification.
          </div>
        )}

        {mode === 'upload' && (
          <div className="upload-zone" style={{ marginBottom: 20 }}>
            <input type="file" accept=".csv" onChange={e => setFile(e.target.files[0])} />
            <div className="upload-icon">📂</div>
            {file
              ? <div className="upload-text" style={{ color: 'var(--accent)' }}>✅ {file.name}</div>
              : <><div className="upload-text">Drop a CSV file here or click to browse</div>
                 <div className="upload-sub">Supported: NSL-KDD, CICIDS, custom network traffic CSV</div></>
            }
          </div>
        )}

        {/* Instance index */}
        <div className="form-group" style={{ maxWidth: 300 }}>
          <label className="form-label">Sample Instance Index</label>
          <input
            className="form-input"
            type="number"
            min={0}
            value={idx}
            onChange={e => setIdx(Number(e.target.value))}
          />
        </div>

        {error && <div className="alert alert-error">⚠️ {error}</div>}

        <button
          id="ids-scan-btn"
          className="btn btn-primary btn-lg"
          onClick={runScan}
          disabled={scanning || (mode === 'upload' && !file)}
        >
          {scanning ? '⏳ Analyzing...' : '🚀 Run IDS Scan'}
        </button>
      </div>

      {/* Scanning animation */}
      {scanning && (
        <div className="card scan-overlay mb-6">
          <div className="spinner" style={{ width: 48, height: 48, borderWidth: 4 }} />
          <p>Analyzing network traffic patterns...</p>
          <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>Running ML inference · Computing SHAP values</p>
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="animate-slide-up">
          {/* Verdict */}
          <div className={`result-box ${result.is_threat ? 'threat' : 'safe'}`}>
            <div className="result-icon">{result.is_threat ? '🚨' : '✅'}</div>
            <div>
              <div className={`result-title ${result.is_threat ? 'result-threat' : 'result-safe'}`}>
                {result.prediction}
              </div>
              <div className="result-subtitle">
                {result.is_threat
                  ? `⚠️ Intrusion pattern detected — ${result.prediction} attack`
                  : '✅ Normal traffic — no threat detected'}
              </div>
            </div>
          </div>

          {/* Confidence + badges */}
          <div className="grid-3 mb-6">
            <div className="metric-card">
              <div className="metric-label">Confidence</div>
              <div className="metric-value accent">{(result.confidence * 100).toFixed(1)}%</div>
              <div className="progress-bar mt-4">
                <div className={`progress-fill ${result.is_threat ? 'danger' : 'success'}`} style={{ width: `${result.confidence * 100}%` }} />
              </div>
            </div>
            <div className={`metric-card ${result.is_threat ? 'danger' : 'success'}`}>
              <div className="metric-label">Classification</div>
              <div className="metric-value" style={{ fontSize: 18, color: result.is_threat ? 'var(--danger)' : 'var(--success)' }}>{result.prediction}</div>
            </div>
            <div className="metric-card purple">
              <div className="metric-label">SHAP Features</div>
              <div className="metric-value" style={{ color: 'var(--purple)' }}>{result.shap_values?.length || 0}</div>
            </div>
          </div>

          {/* Tabs for XAI */}
          <div className="tabs">
            {[['shap', '🔍 SHAP Explanation'], ['features', '📋 Feature Values']].map(([k, label]) => (
              <button key={k} className={`tab-btn ${activeTab === k ? 'active' : ''}`} onClick={() => setActiveTab(k)}>
                {label}
              </button>
            ))}
          </div>

          {activeTab === 'shap' && (
            <ShapChart shapValues={result.shap_values} title="SHAP Feature Contributions — IDS Prediction" />
          )}

          {activeTab === 'features' && (
            <div className="card">
              <div className="section-title">📋 Input Feature Values</div>
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr><th>Feature</th><th>Value</th></tr>
                  </thead>
                  <tbody>
                    {Object.entries(result.instance || {}).map(([k, v]) => (
                      <tr key={k}>
                        <td className="font-mono">{k}</td>
                        <td className="font-mono" style={{ color: 'var(--accent)' }}>{typeof v === 'number' ? v.toFixed(4) : String(v)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </>
  )
}
