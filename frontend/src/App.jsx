import React from 'react'

export default function App() {
  return (
    <div style={{fontFamily: 'system-ui, Arial, sans-serif', padding: '1rem'}}>
      <h2>Healthcare Widget</h2>
      <p>Quick patient summary</p>
      <ul>
        <li>Patients today: <strong>12</strong></li>
        <li>Open appointments: <strong>3</strong></li>
        <li>Critical alerts: <strong style={{color: 'crimson'}}>1</strong></li>
      </ul>
    </div>
  )
}
