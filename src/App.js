import React, { useState } from 'react';
import SignUp from './pages/SignUp';
import VerifyEmail from './pages/VerifyEmail';
import SetupTOTP from './pages/SetupTOTP';
import Login from './pages/Login';
import TOTPVerify from './pages/TOTPVerify';
import Success from './pages/Success';

export default function App() {
  const [view, setView] = useState('signup');
  const [ctx, setCtx] = useState({});

  function goto(v, data = {}) {
    setCtx(prev => ({ ...prev, ...data }));
    setView(v);
  }

  return (
    <div style={{ maxWidth: 700, margin: '20px auto', fontFamily: 'Arial, sans-serif' }}>
      <h2>MFA Option A — Demo</h2>
      {view === 'signup' && <SignUp onNext={(data)=> goto('verify', data)} />}
      {view === 'verify' && <VerifyEmail ctx={ctx} onNext={(data)=> goto('setup-totp', data)} onBack={()=> goto('signup')} />}
      {view === 'setup-totp' && <SetupTOTP ctx={ctx} onNext={()=> goto('login', ctx)} />}
      {view === 'login' && <Login onNext={(data)=> goto('verify-totp', data)} />}
      {view === 'verify-totp' && <TOTPVerify ctx={ctx} onNext={(data)=> goto('success', data)} />}
      {view === 'success' && <Success ctx={ctx} />}
    </div>
  );
}

