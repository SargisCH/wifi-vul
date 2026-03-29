import type { Finding } from "../api/scan";
import SeverityBadge from "./SeverityBadge";

export default function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-4 space-y-2">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <span className="font-semibold text-slate-100">{finding.title}</span>
        <SeverityBadge severity={finding.severity} />
      </div>

      {(finding.interface || finding.profile) && (
        <div className="flex gap-2 flex-wrap">
          {finding.interface && (
            <span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded">
              iface: {finding.interface}
            </span>
          )}
          {finding.profile && (
            <span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded">
              profile: {finding.profile}
            </span>
          )}
        </div>
      )}

      <p className="text-sm text-slate-400">{finding.description}</p>

      <div className="text-sm text-slate-300 bg-slate-900 rounded px-3 py-2 border-l-2 border-blue-500">
        <span className="text-blue-400 font-semibold">Fix: </span>
        {finding.recommendation}
      </div>
    </div>
  );
}
