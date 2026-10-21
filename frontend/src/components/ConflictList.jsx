import { useState } from "react";
import { ChevronDown, ChevronUp, User, Clock, Gauge } from "lucide-react";

const SEVERITY_STYLES = {
  high: "border-l-red-500 bg-red-500/[0.03]",
  medium: "border-l-amber-500 bg-amber-500/[0.03]",
  low: "border-l-slate-500 bg-slate-500/[0.03]",
};
const TYPE_BADGE = {
  subsumption: "bg-red-500/15 text-red-400",
  shadowing: "bg-orange-500/15 text-orange-400",
  policy_induced_failure: "bg-amber-500/15 text-amber-400",
  cross_domain_misalignment: "bg-violet-500/15 text-violet-400",
};
const LEVEL = {
  High: "bg-emerald-500/15 text-emerald-400",
  Medium: "bg-amber-500/15 text-amber-400",
  Low: "bg-red-500/15 text-red-400",
  Shared: "bg-violet-500/15 text-violet-400",
};
function statusStyle(s = "") {
  if (s.startsWith("confirmed")) return "bg-red-500/15 text-red-400";
  if (s.startsWith("advisory")) return "bg-slate-500/20 text-slate-300";
  return "bg-amber-500/15 text-amber-400";
}

function ConflictCard({ conflict }) {
  const [expanded, setExpanded] = useState(false);
  const a = conflict.formal_attribution;
  const level = a?.review_priority || a?.confidence_label;
  const chipText = a?.review_priority
    ? `Review priority: ${a.review_priority}`
    : a?.confidence_label === "Shared"
    ? "Shared responsibility"
    : a?.confidence_label
    ? `${a.confidence_label} confidence`
    : null;

  return (
    <div className={`border-l-2 rounded-xl p-4 border border-white/[0.06] ${SEVERITY_STYLES[conflict.severity] || SEVERITY_STYLES.medium}`}>
      <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`px-2.5 py-1 rounded-md text-[11px] font-medium uppercase tracking-wide ${TYPE_BADGE[conflict.conflict_type] || "bg-slate-500/15 text-slate-400"}`}>
            {conflict.conflict_type?.replace(/_/g, " ")}
          </span>
          {conflict.finding_status && (
            <span className={`px-2 py-0.5 rounded-md text-[10px] font-medium ${statusStyle(conflict.finding_status)}`}>
              {conflict.finding_status}
            </span>
          )}
          <div className="flex items-center gap-1.5 text-slate-400 text-xs">
            <User size={12} />
            {conflict.at_fault_team}
          </div>
          {chipText && (
            <span className={`flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium ${LEVEL[level] || "bg-slate-500/15 text-slate-400"}`}>
              <Gauge size={10} />
              {chipText}
            </span>
          )}
        </div>
        {expanded ? <ChevronUp size={16} className="text-slate-500" /> : <ChevronDown size={16} className="text-slate-500" />}
      </div>
      {expanded && (
        <div className="mt-3 pt-3 border-t border-white/[0.06] space-y-2">
          <p className="text-slate-300 text-sm leading-relaxed">{conflict.explanation}</p>
          {conflict.evidence && <p className="text-slate-500 text-xs">Evidence: {conflict.evidence}</p>}
          {a && (
            <div className="bg-white/[0.03] rounded-lg p-3 mt-2">
              <div className="flex items-center gap-1.5 text-slate-500 text-[11px] mb-1">
                <Clock size={11} /> Attribution reasoning
              </div>
              <p className="text-slate-400 text-xs leading-relaxed">{a.reasoning}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ConflictList({ conflicts, filter }) {
  const filtered = filter === "all" ? conflicts : conflicts.filter((c) => c.conflict_type === filter);
  if (filtered.length === 0) {
    return <div className="text-center py-12 text-slate-500 text-sm">No findings match this filter.</div>;
  }
  return <div className="space-y-3">{filtered.map((c, i) => <ConflictCard key={i} conflict={c} />)}</div>;
}
