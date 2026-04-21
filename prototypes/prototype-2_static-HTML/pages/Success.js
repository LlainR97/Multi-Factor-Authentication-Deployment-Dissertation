import React, { useState } from 'react';
import { apiPost } from '../api';

export default function Success({ ctx }) {
  const [answers, setAnswers] = useState({ ease: 5, comments: '' });
  const [msg, setMsg] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setMsg('Submitting...');
    try {
      const res = await apiPost('/submit-questionnaire', {
        userId: ctx.userId,
        metricId: ctx.metricId,
        uniqueCode: ctx.uniqueCode,
        answers
      });
      if (res.message) setMsg('Thanks! Response recorded.');
      else setMsg('Error: ' + (res.error || 'unknown'));
    } catch (err) {
      setMsg('Error: Could not connect to server');
    }
  };

  return (
    <div>
      <h3>Successfully logged in</h3>
      <p><b>Your unique code:</b> <code>{ctx.uniqueCode}</code></p>

      <form onSubmit={submit}>
        <div>
          <label>How easy was the sign-in (1-7)?</label><br/>
          <input type="number" min="1" max="7" value={answers.ease} onChange={e=>setAnswers({...answers, ease: Number(e.target.value)})} />
        </div>
        <div>
          <label>Any comments?</label><br/>
          <textarea value={answers.comments} onChange={e=>setAnswers({...answers, comments: e.target.value})} />
        </div>
        <button type="submit">Submit questionnaire</button>
      </form>
      <div style={{marginTop:10}}>{msg}</div>
    </div>
  );
}
