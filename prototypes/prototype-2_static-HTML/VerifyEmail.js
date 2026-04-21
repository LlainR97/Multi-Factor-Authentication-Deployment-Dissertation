import React, { useState } from 'react';
import { apiPost } from '../api';

export default function VerifyEmail({ ctx, onNext, onBack }) {
  const [code, setCode] = useState('');
  const [msg, setMsg] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setMsg('Verifying...');
    try {
      const res = await apiPost('/verify-email', { userId: ctx.userId, code });
      if (res.qrDataURL) {
        setMsg('Verified. Scan the QR to enable TOTP.');
        onNext({ ...ctx, qrDataURL: res.qrDataURL });
      } else {
        setMsg('Error: ' + (res.error || 'unknown'));
      }
    } catch (err) {
      setMsg('Error: Could not connect to server');
    }
  };

  return (
    <div>
      <p>We sent a 6-digit code to <b>{ctx.email}</b>. Enter it below:</p>
      <form onSubmit={submit}>
        <input value={code} onChange={e=>setCode(e.target.value)} required />
        <button type="submit">Verify code</button>
      </form>
      <div style={{marginTop:10}}>{msg}</div>
      <div style={{marginTop:10}}><button onClick={onBack}>Back</button></div>
    </div>
  );
}
