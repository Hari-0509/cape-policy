import { useState } from "react";
import { ChevronDown, ChevronUp, User, Clock, Gauge } from "lucide-react";

const SEVERITY_STYLES = {
  high: "border-l-red-500 bg-red-500/[0.03]",
  medium: "border-l-amber-500 bg-amber-500/[0.03]",
  low: "border-l-emerald-500 bg-emerald-500/[0.03]",
};

const TYPE_BADGE = {
  subsumption: "bg-red-500/15 text-red-400",
  shadowing: "bg-orange-500/15 text-orange-400",
  contradiction: "bg-amber-500/15 text-amber-400",
  cross_domain_misalignment: "bg-violet-500/15 text-violet-400",
};

const CONFIDENCE_STYLES = {
  "High": "bg-emerald-500/15 text-emerald-400",
  "Medium-High": "bg-emerald-500/10 text-emerald-500",
  "Medium": "bg-amber-500/15 text-amber-400",
  "Low": "bg-red-500/15 text-red-400",
};

function ConflictCard({ conflict }) {
  const [expanded, setExpanded] = useState(false);
  const attribution = conflict.formal_attribution;

  return (
    <div
      className={`border-l-2 rounded-xl p-4 border border-white/[0.06] ${
        SEVERITY_STYLES[conflict.severity] || SEVERITY_STYLES.medium
      }`}
    >
      <div
        className="flex items-center justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3 flex-wrap">
          <span
            className={`px-2.5 py-1 rounded-md text-[11px] font-medium uppercase tracking-wide ${
              TYPE_BADGE[conflict.conflict_type] || "bg-slate-500/15 text-slate-400"
            }`}
          >
            {conflict.conflict_type?.replace(/_/g, " ")}
          </span>
          <div className="flex items-center gap-1.5 text-slate-400 text-xs">
            <User size={12} />
            {conflict.at_fault_team}
          </div>
          {attribution && (
            <span
              className={`flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium ${
                CONFIDENCE_STYLES[attribution.confidence_label] || "bg-slate-500/15 text-slate-400"
              }`}
            >
              <Gauge size={10} />
              {attribution.confidence_label} confidence
            </span>
          )}
        </div>
        {expanded ? (
          <ChevronUp size={16} className="text-slate-500" />
        ) : (
          <ChevronDown size={16} className="text-slate-500" />
        )}
      </div>

      {expanded && (
        <div className="mt-3 pt-3 border-t border-white/[0.06] space-y-2">
          <p className="text-slate-300 text-sm leading-relaxed">
            {conflict.explanation}
          </p>
          {attribution && (
            <div className="bg-white/[0.03] rounded-lg p-3 mt-2">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-1.5 text-slate-500 text-[11px]">
                  <Clock size={11} />
                  Attribution reasoning
                </div>
                <span className="text-slate-500 text-[11px]">
                  Confidence score: {attribution.confidence_score}
                </span>
              </div>
              <p className="text-slate-400 text-xs leading-relaxed">
                {attribution.reasoning}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ConflictList({ conflicts, filter }) {
  const filtered =
    filter === "all"
      ? conflicts
      : conflicts.filter((c) => c.conflict_type === filter);

  if (filtered.length === 0) {
    return (
      <div className="text-center py-12 text-slate-500 text-sm">
        No conflicts match this filter.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {filtered.map((c, i) => (
        <ConflictCard key={i} conflict={c} />
      ))}
    </div>
  );
}
