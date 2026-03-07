import { Link, Route, Routes } from 'react-router-dom'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'

export default function App() {
  return (
    <div style={{ fontFamily: 'sans-serif', maxWidth: 720, margin: '2rem auto' }}>
      <h1>Sovereign</h1>
      <nav style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
        <Link to="/">Dashboard</Link>
        <Link to="/login">Login</Link>
        <Link to="/register">Register</Link>
      </nav>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
      </Routes>
    </div>
  )
}
