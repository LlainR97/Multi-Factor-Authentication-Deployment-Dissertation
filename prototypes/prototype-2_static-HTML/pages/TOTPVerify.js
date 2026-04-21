import React, { useState } from 'react';
import { apiPost } from '../api';

export default function TOTPVerify({ ctx, onNext }) {
  const [token, setToken] = useState('');
  const [msg, setMsg] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setMsg('Verifying TOTP...');
    try {
      const res = await apiPost('/verify-totp', { userId: ctx.userId, metricId: ctx.metricId, token });
      if (res.uniqueCode) {
        setMsg('Success');
        onNext({ ...ctx, uniqueCode: res.uniqueCode });
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
        <label>Authenticator code</label><br/>
        <input value={token} onChange={e=>setToken(e.target.value)} required />
      </div>
      <button type="submit">Verify</button>
      <div style={{marginTop:10}}>{msg}</div>
    </form>
  );
}
