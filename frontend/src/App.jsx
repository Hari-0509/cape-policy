import { useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Login from "./pages/Login";

function DashboardPlaceholder({ token, username, onLogout }) {
  return (
    <div className="min-h-screen bg-slate-950 text-white p-8">
      <p>Logged in as {username}. Dashboard coming in the next step.</p>
      <button
        onClick={onLogout}
        className="mt-4 text-sm text-red-400 underline"
      >
        Log out
      </button>
    </div>
  );
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem("cape_token"));
  const [username, setUsername] = useState(localStorage.getItem("cape_user"));

  function handleLogin(newToken, newUsername) {
    setToken(newToken);
    setUsername(newUsername);
    localStorage.setItem("cape_token", newToken);
    localStorage.setItem("cape_user", newUsername);
  }

  function handleLogout() {
    setToken(null);
    setUsername(null);
    localStorage.removeItem("cape_token");
    localStorage.removeItem("cape_user");
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/login"
          element={token ? <Navigate to="/dashboard" /> : <Login onLogin={handleLogin} />}
        />
        <Route
          path="/dashboard"
          element={
            token ? (
              <DashboardPlaceholder token={token} username={username} onLogout={handleLogout} />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route path="*" element={<Navigate to="/login" />} />
      </Routes>
    </BrowserRouter>
  );
}
