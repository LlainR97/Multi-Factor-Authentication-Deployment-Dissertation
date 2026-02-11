export const API_BASE = 'http://localhost:4000/api';

export async function apiPost(endpoint, data) {
  const res = await fetch(`http://localhost:3000${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json(); // <-- ensure JSON response
}