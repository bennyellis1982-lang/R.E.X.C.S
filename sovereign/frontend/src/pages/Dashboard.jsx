import { useState } from 'react'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default function Dashboard() {
  const [profile, setProfile] = useState(null)
  const [error, setError] = useState('')

  async function loadProfile() {
    setError('')
    const token = localStorage.getItem('token')
    if (!token) {
      setError('No token found. Please log in first.')
      return
    }

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

  return (
    <div>
      <h2>Dashboard</h2>
      <button onClick={loadProfile}>Load My Profile</button>
      {error && <p style={{ color: 'crimson' }}>{error}</p>}
      {profile && (
        <pre>{JSON.stringify(profile, null, 2)}</pre>
      )}
    </div>
  )
}
