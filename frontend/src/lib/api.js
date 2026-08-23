const API_BASE = "/api";

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error("Invalid credentials");
  return res.json();
}

export async function getConflicts(token) {
  const res = await fetch(`${API_BASE}/conflicts`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to fetch conflicts");
  return res.json();
}

export async function triggerScan(token) {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Scan failed");
  return res.json();
}
