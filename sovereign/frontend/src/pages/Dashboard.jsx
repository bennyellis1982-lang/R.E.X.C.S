import { useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default function Dashboard() {
  const [profile, setProfile] = useState(null)
  const [error, setError] = useState('')
  const [pairingCode, setPairingCode] = useState(null)

  function getToken() {
    const token = localStorage.getItem('token')
    if (!token) {
      setError('No token found. Please log in first.')
      return null
    }
    return token
  }

  async function loadProfile() {
    setError('')
    const token = getToken()
    if (!token) return

    const response = await fetch(`${API_URL}/me`, {
      headers: { Authorization: `Bearer ${token}` }
    })
    const data = await response.json()
    if (!response.ok) {
      setError(data.detail || 'Failed to load profile')
      return
    }
    setProfile(data)
  }

  async function createPairingCode() {
    setError('')
    setPairingCode(null)
    const token = getToken()
    if (!token) return

    const response = await fetch(`${API_URL}/pairing/ipad`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` }
    })
    const data = await response.json()
    if (!response.ok) {
      setError(data.detail || 'Failed to create pairing code')
      return
    }
    setPairingCode(data)
  }

  return (
    <div>
      <h2>Dashboard</h2>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <button onClick={loadProfile}>Load My Profile</button>
        <button onClick={createPairingCode}>Get iPad Pairing Code</button>
      </div>
      {error && <p style={{ color: 'crimson' }}>{error}</p>}
      {pairingCode && (
        <section style={{ border: '1px solid #ddd', borderRadius: 8, marginTop: 16, padding: 16 }}>
          <h3>iPad Pairing Code</h3>
          <p style={{ fontSize: 32, fontWeight: 700, letterSpacing: 4, margin: '8px 0' }}>
            {pairingCode.code}
          </p>
          <p>Enter this code on your {pairingCode.device}. It expires at {new Date(pairingCode.expires_at).toLocaleTimeString()}.</p>
        </section>
      )}
      {profile && (
        <pre>{JSON.stringify(profile, null, 2)}</pre>
      )}
    </div>
  )
}
