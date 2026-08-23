import { AlertTriangle, ShieldAlert, Users, Activity } from "lucide-react";

const ICONS = {
  total: Activity,
  high: ShieldAlert,
  medium: AlertTriangle,
  teams: Users,
};

function StatCard({ label, value, icon: Icon, accent }) {
  return (
    <div className="bg-white/[0.03] backdrop-blur-xl border border-white/[0.08] rounded-2xl p-5 flex-1">
      <div className="flex items-center justify-between mb-3">
        <span className="text-slate-400 text-xs font-medium">{label}</span>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${accent}`}>
          <Icon size={15} className="text-white" />
        </div>
      </div>
      <div className="text-white text-3xl font-semibold tracking-tight">{value}</div>
    </div>
  );
}

export default function StatsOverview({ data }) {
  if (!data) return null;

  const highCount = data.by_severity?.high || 0;
  const mediumCount = data.by_severity?.medium || 0;
  const teamsInvolved = new Set(
    data.conflicts?.map((c) => c.at_fault_team).filter(Boolean)
  ).size;

  return (
    <div className="grid grid-cols-4 gap-4 mb-6">
      <StatCard
        label="Total Conflicts"
        value={data.total || 0}
        icon={ICONS.total}
        accent="bg-gradient-to-br from-blue-500 to-indigo-600"
      />
      <StatCard
        label="High Severity"
        value={highCount}
        icon={ICONS.high}
        accent="bg-gradient-to-br from-red-500 to-rose-600"
      />
      <StatCard
        label="Medium Severity"
        value={mediumCount}
        icon={ICONS.medium}
        accent="bg-gradient-to-br from-amber-500 to-orange-600"
      />
      <StatCard
        label="Teams Involved"
        value={teamsInvolved}
        icon={ICONS.teams}
        accent="bg-gradient-to-br from-emerald-500 to-teal-600"
      />
    </div>
  );
}
