import React, { useState } from 'react';
import { apiPost } from '../api';

export default function Login({ onNext }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [msg, setMsg] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setMsg('Logging in...');
    try {
      const res = await apiPost('/login', { email, password });
      if (res.userId && res.metricId) {
        onNext({ userId: res.userId, metricId: res.metricId });
      } else {
        setMsg('Error: ' + (res.error || 'unknown'));
      }
    } catch (err) {
      setMsg('Error: Could not connect to server');
    }
  };

  return (
    <form onSubmit={submit}>
      <div>
        <label>Email</label><br/>
        <input value={email} onChange={e=>setEmail(e.target.value)} required />
      </div>
      <div>
        <label>Password</label><br/>
        <input value={password} onChange={e=>setPassword(e.target.value)} type="password" required />
      </div>
      <button type="submit">Login</button>
      <div style={{marginTop:10}}>{msg}</div>
    </form>
  );
}
