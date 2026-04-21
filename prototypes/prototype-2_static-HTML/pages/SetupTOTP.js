import React from 'react';

export default function SetupTOTP({ ctx, onNext }) {
  return (
    <div>
      <p>Scan this QR code with Google Authenticator / Authy:</p>
      <div style={{background:'#fff', padding:10, display:'inline-block'}}>
        <img src={ctx.qrDataURL} alt="TOTP QR" />
      </div>
      <p>After scanning, click Next and then use the Authenticator app to generate codes while logging in.</p>
      <button onClick={onNext}>Next → Login</button>
    </div>
  );
}
