'use client'
import { useRouter, usePathname } from 'next/navigation'

const NAV_ITEMS = [
  { icon: '📊', label: 'Dashboard',       path: '/dashboard' },
  { icon: '🔍', label: 'IDS Scanner',     path: '/ids' },
  { icon: '🦠', label: 'Malware Scanner', path: '/malware' },
  { icon: '📋', label: 'Scan History',    path: '/history' },
  { icon: '🤖', label: 'Model Insights',  path: '/insights' },
]

export default function Sidebar({ user, onLogout }) {
  const router   = useRouter()
  const pathname = usePathname()

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <h1>🛡️ XAI-Sec</h1>
        <p>Explainable AI · Cybersecurity</p>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <span className="nav-section-label">Main Menu</span>
        {NAV_ITEMS.map(item => (
          <button
            key={item.path}
            className={`nav-item ${pathname === item.path ? 'active' : ''}`}
            onClick={() => router.push(item.path)}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      {/* System status */}
      <div style={{ padding: '0 16px 8px', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span className="status-dot" />
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>API Connected</span>
      </div>

      {/* User card */}
      <div className="sidebar-user">
        <div className="user-card">
          <div className="user-name">👤 {user?.username || 'Analyst'}</div>
          <div className="user-email">{user?.email || ''}</div>
          <button className="btn-logout" onClick={onLogout}>
            🔴 Sign Out
          </button>
        </div>
      </div>
    </aside>
  )
}
