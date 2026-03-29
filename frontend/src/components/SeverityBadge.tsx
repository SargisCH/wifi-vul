import type { Severity } from "../api/scan";

const styles: Record<Severity, string> = {
  critical: "bg-red-500/20 text-red-400 border border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-400 border border-blue-500/40",
  info: "bg-slate-500/20 text-slate-400 border border-slate-500/40",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${styles[severity]}`}>
      {severity}
    </span>
  );
}
