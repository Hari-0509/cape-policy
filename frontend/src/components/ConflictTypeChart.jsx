import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";

const COLORS = {
  subsumption: "#ef4444",
  shadowing: "#f97316",
  contradiction: "#f59e0b",
  cross_domain_misalignment: "#8b5cf6",
};

export default function ConflictTypeChart({ data }) {
  if (!data || !data.by_type) return null;

  const chartData = Object.entries(data.by_type).map(([type, count]) => ({
    name: type.replace(/_/g, " "),
    value: count,
    color: COLORS[type] || "#64748b",
  }));

  return (
    <div className="bg-white/[0.03] backdrop-blur-xl border border-white/[0.08] rounded-2xl p-5">
      <h3 className="text-white text-sm font-medium mb-4">Conflicts by Type</h3>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={chartData}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={80}
            paddingAngle={4}
          >
            {chartData.map((entry, i) => (
              <Cell key={i} fill={entry.color} stroke="none" />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "#0f172a",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: "8px",
              fontSize: "12px",
              color: "#fff",
            }}
          />
          <Legend
            iconType="circle"
            wrapperStyle={{ fontSize: "11px", color: "#94a3b8" }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
