import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../lib/api";
import { ShieldCheck, Lock, User, ArrowRight, Network } from "lucide-react";

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await login(username, password);
      onLogin(data.token, data.username);
      navigate("/dashboard");
    } catch (err) {
      setError("Invalid username or password");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0e17] relative overflow-hidden flex items-center justify-center px-4">
      {/* Background gradient orbs */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-600/20 rounded-full blur-3xl" />
      <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-indigo-600/20 rounded-full blur-3xl" />

      {/* Grid pattern overlay */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage:
            "linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />

      <div className="w-full max-w-md relative z-10">
        {/* Logo / branding */}
        <div className="flex flex-col items-center mb-10">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20 mb-4">
            <Network className="text-white" size={26} strokeWidth={2} />
          </div>
          <h1 className="text-white text-2xl font-semibold tracking-tight">
            CAPE-Policy
          </h1>
          <p className="text-slate-500 text-sm mt-1.5 text-center max-w-xs">
            Ownership-Aware Cross-Policy Conflict Analysis
          </p>
        </div>

        {/* Login card */}
        <div className="bg-white/[0.03] backdrop-blur-xl border border-white/[0.08] rounded-2xl p-8 shadow-2xl">
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="text-slate-400 text-xs font-medium mb-2 flex items-center gap-1.5">
                <User size={13} />
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full bg-white/[0.04] border border-white/[0.08] rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-blue-500/60 focus:bg-white/[0.06] transition-all placeholder:text-slate-600"
                placeholder="admin"
                required
                autoComplete="username"
              />
            </div>

            <div>
              <label className="text-slate-400 text-xs font-medium mb-2 flex items-center gap-1.5">
                <Lock size={13} />
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-white/[0.04] border border-white/[0.08] rounded-xl px-4 py-3 text-white text-sm outline-none focus:border-blue-500/60 focus:bg-white/[0.06] transition-all placeholder:text-slate-600"
                placeholder="••••••••"
                required
                autoComplete="current-password"
              />
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                <p className="text-red-400 text-xs">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-sm font-medium rounded-xl py-3 transition-all disabled:opacity-50 flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20 group"
            >
              {loading ? (
                "Signing in..."
              ) : (
                <>
                  Sign in
                  <ArrowRight size={15} className="group-hover:translate-x-0.5 transition-transform" />
                </>
              )}
            </button>
          </form>
        </div>

        <div className="flex items-center justify-center gap-1.5 mt-6 text-slate-600 text-xs">
          <ShieldCheck size={13} />
          <span>Cross-team Kubernetes policy governance</span>
        </div>
      </div>
    </div>
  );
}
