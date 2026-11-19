import './globals.css'

export const metadata = {
  title: '🛡️ XAI-Sec Dashboard',
  description: 'Explainable AI for Cybersecurity — SOC Platform',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
