import { useEffect, useState } from "react";
import { getConflicts, triggerScan } from "../lib/api";
import StatsOverview from "../components/StatsOverview";
import ConflictTypeChart from "../components/ConflictTypeChart";
import TeamFilterBar from "../components/TeamFilterBar";
import ConflictList from "../components/ConflictList";
import { Network, LogOut, RefreshCw } from "lucide-react";

export default function Dashboard({ token, username, onLogout }) {
  const [data, setData] = useState(null);
  const [filter, setFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);

  async function fetchData() {
    try {
      const result = await getConflicts(token);
      setData(result);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  async function handleRescan() {
    setScanning(true);
    try {
      await triggerScan(token);
      await fetchData();
    } catch (err) {
      console.error(err);
    } finally {
      setScanning(false);
    }
  }

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0e17]">
      {/* Header */}
      <header className="border-b border-white/[0.06] px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center">
            <Network className="text-white" size={16} />
          </div>
          <span className="text-white font-semibold text-sm">CAPE-Policy</span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRescan}
            disabled={scanning}
            className="flex items-center gap-1.5 bg-white/[0.05] hover:bg-white/[0.08] text-slate-300 text-xs font-medium px-3 py-2 rounded-lg transition-all disabled:opacity-50"
          >
            <RefreshCw size={13} className={scanning ? "animate-spin" : ""} />
            {scanning ? "Scanning..." : "Re-scan cluster"}
          </button>
          <div className="text-slate-500 text-xs">{username}</div>
          <button
            onClick={onLogout}
            className="flex items-center gap-1.5 text-slate-500 hover:text-red-400 text-xs transition-colors"
          >
            <LogOut size={13} />
          </button>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-6xl mx-auto px-8 py-8">
        <div className="mb-6">
          <h1 className="text-white text-xl font-semibold mb-1">
            Policy Conflict Overview
          </h1>
          <p className="text-slate-500 text-sm">
            Cross-team security policy conflicts detected across your Kubernetes cluster
          </p>
        </div>

        {loading ? (
          <div className="text-slate-500 text-sm py-12 text-center">
            Loading scan results...
          </div>
        ) : (
          <>
            <StatsOverview data={data} />

            <div className="grid grid-cols-3 gap-4 mb-6">
              <div className="col-span-2">
                <TeamFilterBar activeFilter={filter} onFilterChange={setFilter} />
                <ConflictList conflicts={data?.conflicts || []} filter={filter} />
              </div>
              <div>
                <ConflictTypeChart data={data} />
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
