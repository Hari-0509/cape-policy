import { Filter } from "lucide-react";

const CONFLICT_TYPES = [
  "all",
  "subsumption",
  "shadowing",
  "contradiction",
  "cross_domain_misalignment",
];

export default function TeamFilterBar({ activeFilter, onFilterChange }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <div className="flex items-center gap-1.5 text-slate-500 text-xs mr-2">
        <Filter size={13} />
        Filter:
      </div>
      {CONFLICT_TYPES.map((type) => (
        <button
          key={type}
          onClick={() => onFilterChange(type)}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
            activeFilter === type
              ? "bg-blue-600 text-white"
              : "bg-white/[0.04] text-slate-400 hover:bg-white/[0.08] hover:text-slate-200"
          }`}
        >
          {type === "all" ? "All" : type.replace(/_/g, " ")}
        </button>
      ))}
    </div>
  );
}
