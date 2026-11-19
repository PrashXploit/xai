'use client'
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Sidebar from '../components/Sidebar'

export default function AppLayout({ children }) {
  const router = useRouter()
  const [user, setUser] = useState(null)

  useEffect(() => {
    const token = localStorage.getItem('xai_token')
    const u     = localStorage.getItem('xai_user')
    if (!token) { router.replace('/'); return }
    if (u) setUser(JSON.parse(u))
  }, [])

  function handleLogout() {
    localStorage.removeItem('xai_token')
    localStorage.removeItem('xai_user')
    router.replace('/')
  }

  return (
    <div className="app-layout">
      <Sidebar user={user} onLogout={handleLogout} />
      <main className="main-content animate-fade-in">
        {children}
      </main>
    </div>
  )
}
