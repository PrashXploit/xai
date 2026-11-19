/**
 * Centralized API client for XAI-Sec backend.
 * All requests go to FastAPI at localhost:8000.
 */

const BASE = typeof window !== 'undefined' && window.location.hostname !== 'localhost'
  ? `http://${window.location.hostname}:8000`
  : 'http://127.0.0.1:8000'

function getToken() {
  if (typeof window === 'undefined') return null
  return localStorage.getItem('xai_token')
}

function authHeaders() {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...options.headers },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  // Auth
  register: (username, email, password) =>
    request('/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password }) }),

  login: (email, password) =>
    request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),

  forgotPassword: (email, new_password) =>
    request('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email, new_password }) }),

  // IDS
  idsSample: () => request('/ids/sample', { headers: authHeaders() }),

  idsScan: async (file, instanceIdx = 0) => {
    const form = new FormData()
    if (file) form.append('file', file)
    form.append('instance_idx', instanceIdx)
    const res = await fetch(`${BASE}/ids/scan?instance_idx=${instanceIdx}`, {
      method: 'POST',
      headers: authHeaders(),
      body: file ? form : undefined,
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
      throw new Error(err.detail || `HTTP ${res.status}`)
    }
    return res.json()
  },

  // Malware
  malwareScan: async (file, instanceIdx = 0) => {
    const form = new FormData()
    if (file) form.append('file', file)
    form.append('instance_idx', instanceIdx)
    const res = await fetch(`${BASE}/malware/scan?instance_idx=${instanceIdx}`, {
      method: 'POST',
      headers: authHeaders(),
      body: file ? form : undefined,
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
      throw new Error(err.detail || `HTTP ${res.status}`)
    }
    return res.json()
  },

  // History
  history: () => request('/history/', { headers: authHeaders() }),
  historySummary: () => request('/history/summary', { headers: authHeaders() }),

  // Model Metrics (individual)
  idsMetrics:     () => request('/models/ids',     { headers: authHeaders() }),
  malwareMetrics: () => request('/models/malware', { headers: authHeaders() }),

  /**
   * Combined model-insights endpoint (future, recommended).
   * Expected shape:
   *   {
   *     ids:     { metrics, per_class_f1, class_labels, confusion_matrix, shap_importances, arch },
   *     malware: { metrics, per_class_f1, class_labels, confusion_matrix, shap_importances, arch }
   *   }
   * Usage: const { ids, malware } = await api.modelInsights()
   */
  modelInsights: () => request('/api/model-insights', { headers: authHeaders() }),
}
