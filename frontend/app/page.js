'use client'
import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { api } from './lib/api'
import Image from 'next/image'

function TypedTagline() {
  const phrases = ['Your Threats. Our Intelligence.', 'Detect. Explain. Protect.', 'AI Security. Fully Transparent.']
  const [phraseIdx, setPhraseIdx] = useState(0)
  const [displayed, setDisplayed] = useState('')
  const [deleting, setDeleting] = useState(false)

  useEffect(() => {
    const current = phrases[phraseIdx]
    let t
    if (!deleting && displayed.length < current.length) {
      t = setTimeout(() => setDisplayed(current.slice(0, displayed.length + 1)), 55)
    } else if (!deleting && displayed.length === current.length) {
      t = setTimeout(() => setDeleting(true), 2200)
    } else if (deleting && displayed.length > 0) {
      t = setTimeout(() => setDisplayed(current.slice(0, displayed.length - 1)), 30)
    } else {
      setDeleting(false)
      setPhraseIdx(i => (i + 1) % phrases.length)
    }
    return () => clearTimeout(t)
  }, [displayed, deleting, phraseIdx])

  return <span className="typed-phrase">{displayed}<span className="typed-cur">|</span></span>
}

export default function AuthPage() {
  const router = useRouter()
  const [tab, setTab] = useState('login')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [form, setForm] = useState({ username: '', email: '', password: '', confirm: '' })
  const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }))

  async function handleLogin(e) {
    e.preventDefault(); setError(''); setLoading(true)
    try {
      const data = await api.login(form.email, form.password)
      localStorage.setItem('xai_token', data.access_token)
      localStorage.setItem('xai_user', JSON.stringify(data.user))
      window.location.href = '/dashboard'
    } catch (err) {
      setError(err.message)
      setLoading(false)
    }
  }

  async function handleRegister(e) {
    e.preventDefault(); setError(''); setSuccess('')
    if (form.password !== form.confirm) return setError('Passwords do not match')
    if (form.password.length < 6) return setError('Password must be at least 6 characters')
    setLoading(true)
    try {
      await api.register(form.username, form.email, form.password)
      setSuccess('Account created! Sign in now.')
      setTab('login')
      setForm(f => ({ ...f, password: '', confirm: '' }))
    } catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }

  async function handleReset(e) {
    e.preventDefault(); setError(''); setSuccess('')
    if (form.password !== form.confirm) return setError('Passwords do not match')
    if (form.password.length < 6) return setError('Password must be at least 6 characters')
    setLoading(true)
    try {
      const res = await api.forgotPassword(form.email, form.password)
      setSuccess(res.message || 'Password reset successfully! You can sign in now.')
      setTab('login')
      setForm(f => ({ ...f, password: '', confirm: '' }))
    } catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');

        * { box-sizing: border-box; margin: 0; padding: 0; }

        .lp {
          font-family: 'Inter', sans-serif;
          min-height: 100vh;
          width: 100%;
          background: #000;
          display: flex;
          flex-direction: column;
          position: relative;
          overflow: hidden;
          -webkit-font-smoothing: antialiased;
        }

        /* ── World-map dot grid bg ─────────────────── */
        .lp-bg {
          position: absolute;
          inset: 0;
          background-image:
            radial-gradient(circle, rgba(255,255,255,0.08) 1px, transparent 1px);
          background-size: 28px 28px;
          mask-image: radial-gradient(ellipse 90% 80% at 55% 45%, black 20%, transparent 85%);
          pointer-events: none;
        }

        /* Colour glows */
        .lp-glow-1 {
          position: absolute;
          width: 700px; height: 700px;
          border-radius: 50%;
          background: radial-gradient(circle, rgba(99,102,241,0.18) 0%, transparent 65%);
          right: -100px; top: -180px;
          pointer-events: none;
        }
        .lp-glow-2 {
          position: absolute;
          width: 500px; height: 500px;
          border-radius: 50%;
          background: radial-gradient(circle, rgba(34,211,238,0.08) 0%, transparent 65%);
          right: 100px; bottom: -100px;
          pointer-events: none;
        }
        .lp-glow-3 {
          position: absolute;
          width: 400px; height: 400px;
          border-radius: 50%;
          background: radial-gradient(circle, rgba(99,102,241,0.06) 0%, transparent 65%);
          left: -80px; top: 30%;
          pointer-events: none;
        }

        /* ── Top Nav ─────────────────────────────── */
        .lp-nav {
          position: relative;
          z-index: 10;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 24px 48px;
        }

        .lp-logo {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .lp-logo-icon {
          width: 40px; height: 40px;
          background: linear-gradient(135deg, #6366f1 0%, #818cf8 100%);
          border-radius: 10px;
          display: flex; align-items: center; justify-content: center;
          font-size: 20px;
          box-shadow: 0 0 24px rgba(99,102,241,0.5);
        }

        .lp-logo-name {
          font-size: 22px;
          font-weight: 900;
          color: #fff;
          letter-spacing: -0.5px;
        }

        .lp-logo-name span { color: #818cf8; }

        .lp-nav-links {
          display: flex;
          align-items: center;
          gap: 32px;
        }

        .lp-nav-link {
          font-size: 13.5px;
          font-weight: 500;
          color: rgba(255,255,255,0.45);
          text-decoration: none;
          transition: color 0.2s;
          cursor: pointer;
        }

        .lp-nav-link:hover { color: rgba(255,255,255,0.85); }

        .lp-nav-badge {
          background: rgba(99,102,241,0.15);
          border: 1px solid rgba(99,102,241,0.3);
          color: #818cf8;
          font-size: 12px;
          font-weight: 600;
          padding: 6px 16px;
          border-radius: 99px;
          cursor: pointer;
          transition: all 0.2s;
        }

        .lp-nav-badge:hover {
          background: rgba(99,102,241,0.25);
        }

        /* ── Main body ───────────────────────────── */
        .lp-body {
          position: relative;
          z-index: 5;
          flex: 1;
          display: grid;
          grid-template-columns: 1fr 1fr;
          align-items: center;
          padding: 0 48px 0 64px;
          gap: 32px;
        }

        /* ── LEFT: Hero ──────────────────────────── */
        .lp-hero {
          display: flex;
          flex-direction: column;
          gap: 0;
        }

        .lp-eyebrow {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 99px;
          padding: 6px 16px;
          font-size: 12px;
          font-weight: 600;
          color: rgba(255,255,255,0.5);
          letter-spacing: 1px;
          text-transform: uppercase;
          width: fit-content;
          margin-bottom: 28px;
        }

        .lp-eyebrow-dot {
          width: 7px; height: 7px;
          border-radius: 50%;
          background: #10b981;
          box-shadow: 0 0 8px rgba(16,185,129,0.8);
          animation: pulse-dot 2s ease-in-out infinite;
        }

        @keyframes pulse-dot {
          0%,100% { opacity:1; transform:scale(1); }
          50% { opacity:0.5; transform:scale(0.8); }
        }

        .lp-title {
          font-size: clamp(48px, 5.5vw, 76px);
          font-weight: 900;
          line-height: 1.0;
          letter-spacing: -2.5px;
          color: #fff;
          margin-bottom: 20px;
        }

        .lp-title .t-dim { color: rgba(255,255,255,0.28); font-weight: 300; }
        .lp-title .t-accent {
          background: linear-gradient(135deg, #818cf8 0%, #22d3ee 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .lp-tagline {
          font-size: 16px;
          color: rgba(255,255,255,0.35);
          letter-spacing: 0.5px;
          font-weight: 400;
          min-height: 26px;
          margin-bottom: 40px;
        }

        .typed-phrase { color: rgba(255,255,255,0.55); }
        .typed-cur {
          color: #6366f1;
          animation: blink 1s step-end infinite;
        }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }

        /* Feature icons row */
        .lp-features {
          display: flex;
          gap: 28px;
          margin-bottom: 48px;
        }

        .lp-feat {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 8px;
          cursor: default;
        }

        .lp-feat-icon {
          width: 52px; height: 52px;
          border-radius: 14px;
          border: 1px solid rgba(255,255,255,0.1);
          background: rgba(255,255,255,0.04);
          display: flex; align-items: center; justify-content: center;
          font-size: 22px;
          transition: all 0.25s;
        }

        .lp-feat:hover .lp-feat-icon {
          border-color: rgba(99,102,241,0.4);
          background: rgba(99,102,241,0.1);
          transform: translateY(-3px);
          box-shadow: 0 8px 24px rgba(99,102,241,0.2);
        }

        .lp-feat-label {
          font-size: 11.5px;
          color: rgba(255,255,255,0.35);
          font-weight: 500;
          letter-spacing: 0.3px;
        }

        /* Protected badge */
        .lp-protected {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          background: rgba(16,185,129,0.08);
          border: 1px solid rgba(16,185,129,0.2);
          border-radius: 12px;
          padding: 10px 18px;
          width: fit-content;
        }

        .lp-protected-dot {
          width: 8px; height: 8px;
          border-radius: 50%;
          background: #10b981;
          box-shadow: 0 0 10px rgba(16,185,129,0.7);
          animation: pulse-dot 2s ease-in-out infinite;
        }

        .lp-protected-text {
          font-size: 13px;
          font-weight: 600;
          color: #34d399;
        }

        .lp-protected-sub {
          font-size: 11.5px;
          color: rgba(52,211,153,0.6);
          margin-left: 4px;
        }

        /* ── RIGHT: Mascot + Form ─────────────────── */
        .lp-right {
          display: flex;
          flex-direction: column;
          align-items: center;
          position: relative;
          padding-bottom: 20px;
        }

        /* Mascot */
        .lp-mascot-wrap {
          position: relative;
          width: 320px;
          height: 320px;
          margin-bottom: -20px;
        }

        .lp-mascot-img {
          width: 100%;
          height: 100%;
          object-fit: contain;
          filter: drop-shadow(0 0 60px rgba(99,102,241,0.35));
          animation: float-mascot 5s ease-in-out infinite;
        }

        @keyframes float-mascot {
          0%,100% { transform: translateY(0px) rotate(0deg); }
          33% { transform: translateY(-12px) rotate(-1deg); }
          66% { transform: translateY(-6px) rotate(1deg); }
        }

        /* Orbit ring */
        .lp-orbit {
          position: absolute;
          width: 280px; height: 80px;
          border-radius: 50%;
          border: 1px solid rgba(99,102,241,0.2);
          top: 50%; left: 50%;
          transform: translate(-50%, -50%);
          animation: spin-orbit 8s linear infinite;
        }

        @keyframes spin-orbit {
          from { transform: translate(-50%,-50%) rotateX(75deg) rotateZ(0deg); }
          to   { transform: translate(-50%,-50%) rotateX(75deg) rotateZ(360deg); }
        }

        .lp-orbit-dot {
          width: 8px; height: 8px;
          border-radius: 50%;
          background: #818cf8;
          box-shadow: 0 0 12px rgba(129,140,248,0.8);
          position: absolute;
          top: -4px; left: calc(50% - 4px);
        }

        /* ── Form Card ───────────────────────────── */
        .lp-form-card {
          width: 100%;
          max-width: 400px;
          background: rgba(255,255,255,0.03);
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 20px;
          padding: 32px;
          backdrop-filter: blur(20px);
          box-shadow: 0 24px 80px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.06);
        }

        .lp-form-title {
          font-size: 18px;
          font-weight: 800;
          color: #fff;
          margin-bottom: 4px;
          letter-spacing: -0.3px;
        }

        .lp-form-sub {
          font-size: 13px;
          color: rgba(255,255,255,0.3);
          margin-bottom: 22px;
        }

        .lp-form-sub a {
          color: #818cf8;
          cursor: pointer;
          text-decoration: none;
          font-weight: 600;
        }

        /* Tabs */
        .lp-tabs {
          display: flex;
          background: rgba(255,255,255,0.04);
          border-radius: 10px;
          padding: 3px;
          margin-bottom: 24px;
          gap: 2px;
        }

        .lp-tab {
          flex: 1;
          padding: 8px;
          border: none;
          border-radius: 8px;
          background: none;
          color: rgba(255,255,255,0.3);
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.15s;
          font-family: 'Inter', sans-serif;
        }

        .lp-tab.active {
          background: rgba(99,102,241,0.2);
          color: #c7d2fe;
          box-shadow: 0 1px 4px rgba(0,0,0,0.3);
        }

        /* Input */
        .lp-input-group { margin-bottom: 14px; }

        .lp-label {
          display: block;
          font-size: 11px;
          font-weight: 600;
          color: rgba(255,255,255,0.3);
          text-transform: uppercase;
          letter-spacing: 0.8px;
          margin-bottom: 6px;
        }

        .lp-input {
          width: 100%;
          padding: 11px 14px;
          background: rgba(0,0,0,0.4);
          border: 1px solid rgba(255,255,255,0.07);
          border-radius: 10px;
          color: #fff;
          font-size: 14px;
          font-family: 'Inter', sans-serif;
          outline: none;
          transition: all 0.15s;
        }

        .lp-input:focus {
          border-color: rgba(99,102,241,0.5);
          box-shadow: 0 0 0 3px rgba(99,102,241,0.12);
        }

        .lp-input::placeholder { color: rgba(255,255,255,0.18); }

        /* Submit */
        .lp-btn {
          width: 100%;
          padding: 13px;
          margin-top: 6px;
          background: linear-gradient(135deg, #5254e7 0%, #818cf8 100%);
          border: none;
          border-radius: 11px;
          color: #fff;
          font-size: 15px;
          font-weight: 700;
          cursor: pointer;
          font-family: 'Inter', sans-serif;
          transition: all 0.2s;
          box-shadow: 0 4px 24px rgba(99,102,241,0.4);
          letter-spacing: -0.2px;
        }

        .lp-btn:hover:not(:disabled) {
          transform: translateY(-1px);
          box-shadow: 0 8px 32px rgba(99,102,241,0.55);
        }

        .lp-btn:disabled { opacity: 0.45; cursor: not-allowed; }

        /* Alerts */
        .lp-alert {
          padding: 10px 13px;
          border-radius: 8px;
          font-size: 12.5px;
          margin-bottom: 14px;
          display: flex;
          align-items: center;
          gap: 7px;
        }

        .lp-alert.err { background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.2); color: #fb7185; }
        .lp-alert.ok  { background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.2); color: #34d399; }

        /* Security row */
        .lp-sec-row {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 16px;
          margin-top: 18px;
          padding-top: 16px;
          border-top: 1px solid rgba(255,255,255,0.05);
        }

        .lp-sec-item {
          display: flex;
          align-items: center;
          gap: 5px;
          font-size: 11px;
          color: rgba(255,255,255,0.22);
          font-weight: 500;
        }

        /* ── Bottom bar ──────────────────────────── */
        .lp-bottom {
          position: relative;
          z-index: 5;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 16px 48px 28px;
        }

        .lp-bottom-left {
          font-size: 12px;
          color: rgba(255,255,255,0.18);
        }

        .lp-stats-row {
          display: flex;
          gap: 28px;
        }

        .lp-stat {
          text-align: center;
        }

        .lp-stat-val {
          font-size: 18px;
          font-weight: 900;
          color: rgba(255,255,255,0.7);
          letter-spacing: -0.5px;
        }

        .lp-stat-val em { color: #818cf8; font-style: normal; }

        .lp-stat-lbl {
          font-size: 10.5px;
          color: rgba(255,255,255,0.2);
          font-weight: 500;
          margin-top: 1px;
        }

        /* Floating badge top-right */
        .lp-connect-badge {
          position: absolute;
          bottom: 28px;
          right: 48px;
          display: flex;
          align-items: center;
          gap: 10px;
          background: rgba(20,20,20,0.8);
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 12px;
          padding: 10px 16px;
          backdrop-filter: blur(16px);
          font-size: 13px;
          color: rgba(255,255,255,0.5);
          font-weight: 500;
          z-index: 6;
        }

        @media (max-width: 900px) {
          .lp-body { grid-template-columns: 1fr; }
          .lp-hero { display: none; }
          .lp-bottom { flex-direction: column; gap: 16px; }
          .lp-nav { padding: 20px 24px; }
          .lp-body { padding: 20px 24px; }
        }
      `}</style>

      <div className="lp">
        {/* Backgrounds */}
        <div className="lp-bg" />
        <div className="lp-glow-1" />
        <div className="lp-glow-2" />
        <div className="lp-glow-3" />

        {/* ── NAV ── */}
        <nav className="lp-nav">
          <div className="lp-logo">
            <div className="lp-logo-icon">🛡️</div>
            <span className="lp-logo-name">XAI<span>-Sec</span></span>
          </div>
          <div className="lp-nav-links">
            <span className="lp-nav-link">Features</span>
            <span className="lp-nav-link">Dashboard</span>
            <span className="lp-nav-link">API Docs</span>
            <span className="lp-nav-badge">v2.0 Live ✦</span>
          </div>
        </nav>

        {/* ── BODY ── */}
        <div className="lp-body">

          {/* LEFT: Hero */}
          <div className="lp-hero">
            <div className="lp-eyebrow">
              <div className="lp-eyebrow-dot" />
              AI-Powered Security Platform
            </div>

            <h1 className="lp-title">
              <span className="t-dim">Cyber</span><br/>
              <span className="t-accent">Security</span><br/>
              Reimagined.
            </h1>

            <p className="lp-tagline">
              <TypedTagline />
            </p>

            <div className="lp-features">
              {[
                { icon: '🔒', label: 'Secure' },
                { icon: '⚡', label: 'Fast' },
                { icon: '🌐', label: 'Global' },
                { icon: '🧠', label: 'Explainable' },
                { icon: '🦠', label: 'Malware' },
              ].map(f => (
                <div className="lp-feat" key={f.label}>
                  <div className="lp-feat-icon">{f.icon}</div>
                  <span className="lp-feat-label">{f.label}</span>
                </div>
              ))}
            </div>

            <div className="lp-protected">
              <div className="lp-protected-dot" />
              <span className="lp-protected-text">You are protected</span>
              <span className="lp-protected-sub">· All systems active</span>
              <span style={{marginLeft:'auto', fontSize:18}}>📶</span>
            </div>
          </div>

          {/* RIGHT: Mascot + Form */}
          <div className="lp-right">
            {/* Mascot */}
            <div className="lp-mascot-wrap">
              <div className="lp-orbit"><div className="lp-orbit-dot" /></div>
              <img src="/mascot.png" alt="XAI-Sec Mascot" className="lp-mascot-img" />
            </div>

            {/* Form Card */}
            <div className="lp-form-card">
              <div className="lp-form-title">
                {tab === 'login' ? '👋 Welcome back' : tab === 'register' ? '✨ Join XAI-Sec' : '🔄 Reset Password'}
              </div>
              <div className="lp-form-sub">
                {tab === 'login'
                  ? <>No account? <a onClick={() => { setTab('register'); setError(''); setSuccess('') }}>Create one free</a></>
                  : tab === 'register'
                  ? <>Have access? <a onClick={() => { setTab('login'); setError(''); setSuccess('') }}>Sign in</a></>
                  : <>Remembered password? <a onClick={() => { setTab('login'); setError(''); setSuccess('') }}>Sign in</a></>
                }
              </div>

              <div className="lp-tabs">
                <button className={`lp-tab ${tab === 'login' ? 'active' : ''}`}
                  onClick={() => { setTab('login'); setError(''); setSuccess('') }}>🔑 Sign In</button>
                <button className={`lp-tab ${tab === 'register' ? 'active' : ''}`}
                  onClick={() => { setTab('register'); setError(''); setSuccess('') }}>✨ Sign Up</button>
                <button className={`lp-tab ${tab === 'forgot' ? 'active' : ''}`}
                  onClick={() => { setTab('forgot'); setError(''); setSuccess('') }}>🔄 Reset</button>
              </div>

              {error   && <div className="lp-alert err">⚠️ {error}</div>}
              {success && <div className="lp-alert ok">✅ {success}</div>}

              {tab === 'login' ? (
                <form onSubmit={handleLogin}>
                  <div className="lp-input-group">
                    <label className="lp-label">Email</label>
                    <input id="login-email" className="lp-input" type="email"
                      placeholder="analyst@soc.com" value={form.email} onChange={set('email')} required />
                  </div>
                  <div className="lp-input-group">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <label className="lp-label">Password</label>
                      <a onClick={() => { setTab('forgot'); setError(''); setSuccess('') }} style={{ color: '#38bdf8', fontSize: '12px', cursor: 'pointer', textDecoration: 'none' }}>Forgot?</a>
                    </div>
                    <input id="login-password" className="lp-input" type="password"
                      placeholder="••••••••" value={form.password} onChange={set('password')} required />
                  </div>
                  <button id="login-submit" className="lp-btn" type="submit" disabled={loading}>
                    {loading ? '⏳ Authenticating...' : '🚀 Access Dashboard →'}
                  </button>
                </form>
              ) : tab === 'register' ? (
                <form onSubmit={handleRegister}>
                  <div className="lp-input-group">
                    <label className="lp-label">Username</label>
                    <input id="reg-username" className="lp-input" type="text"
                      placeholder="analyst01" value={form.username} onChange={set('username')} required />
                  </div>
                  <div className="lp-input-group">
                    <label className="lp-label">Email</label>
                    <input id="reg-email" className="lp-input" type="email"
                      placeholder="analyst@soc.com" value={form.email} onChange={set('email')} required />
                  </div>
                  <div className="lp-input-group">
                    <label className="lp-label">Password</label>
                    <input id="reg-password" className="lp-input" type="password"
                      placeholder="Min. 6 chars" value={form.password} onChange={set('password')} required />
                  </div>
                  <div className="lp-input-group">
                    <label className="lp-label">Confirm</label>
                    <input id="reg-confirm" className="lp-input" type="password"
                      placeholder="Repeat password" value={form.confirm} onChange={set('confirm')} required />
                  </div>
                  <button id="reg-submit" className="lp-btn" type="submit" disabled={loading}>
                    {loading ? '⏳ Creating...' : '✅ Create SOC Account →'}
                  </button>
                </form>
              ) : (
                <form onSubmit={handleReset}>
                  <div className="lp-input-group">
                    <label className="lp-label">Registered Email</label>
                    <input id="reset-email" className="lp-input" type="email"
                      placeholder="analyst@soc.com" value={form.email} onChange={set('email')} required />
                  </div>
                  <div className="lp-input-group">
                    <label className="lp-label">New Password</label>
                    <input id="reset-password" className="lp-input" type="password"
                      placeholder="Min. 6 chars" value={form.password} onChange={set('password')} required />
                  </div>
                  <div className="lp-input-group">
                    <label className="lp-label">Confirm New Password</label>
                    <input id="reset-confirm" className="lp-input" type="password"
                      placeholder="Repeat new password" value={form.confirm} onChange={set('confirm')} required />
                  </div>
                  <button id="reset-submit" className="lp-btn" type="submit" disabled={loading}>
                    {loading ? '⏳ Updating...' : '🔄 Update Password →'}
                  </button>
                </form>
              )}

              <div className="lp-sec-row">
                <div className="lp-sec-item">🔒 bcrypt</div>
                <div className="lp-sec-item">🪪 JWT Auth</div>
                <div className="lp-sec-item">🛡️ Encrypted</div>
              </div>
            </div>
          </div>
        </div>

        {/* ── BOTTOM BAR ── */}
        <div className="lp-bottom">
          <div className="lp-bottom-left">
            © 2026 XAI-Sec · Built by Prashanth · MIT License
          </div>
          <div className="lp-stats-row">
            <div className="lp-stat">
              <div className="lp-stat-val"><em>99.2%</em></div>
              <div className="lp-stat-lbl">Detection Rate</div>
            </div>
            <div className="lp-stat">
              <div className="lp-stat-val"><em>1M+</em></div>
              <div className="lp-stat-lbl">Threats Analyzed</div>
            </div>
            <div className="lp-stat">
              <div className="lp-stat-val"><em>&lt;50ms</em></div>
              <div className="lp-stat-lbl">Scan Speed</div>
            </div>
            <div className="lp-stat">
              <div className="lp-stat-val"><em>2</em></div>
              <div className="lp-stat-lbl">XAI Engines</div>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
