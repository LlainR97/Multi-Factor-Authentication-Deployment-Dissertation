import React, { useState } from 'react';
import { apiPost } from '../api';

export default function SignUp({ onNext }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [msg, setMsg] = useState('');

  // <<< Replace the old submit() function with this one
  const submit = async (e) => {
    e.preventDefault();
    setMsg('Signing up...');
    try {
      const res = await apiPost('/signup', { email, password });
      console.log("Signup response:", res); // <-- debug API response

      // Adjust this to match your backend response
      if (res.userId || res.success) {
        setMsg('Verification code sent — check email');
        // Use userId if available, otherwise just pass email
        onNext({ userId: res.userId || email, email });
      } else {
        setMsg('Error: ' + (res.error || 'unknown'));
      }
    } catch (err) {
      console.error(err);
      setMsg('Error: Could not connect to server');
    }
  };
  // <<< End of replacement

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
      <button type="submit">Create account</button>
      <div style={{marginTop:10}}>{msg}</div>
    </form>
  );
}
