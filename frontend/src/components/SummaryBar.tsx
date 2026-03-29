import type { ScanResult } from "../api/scan";

const items = [
  { key: "critical" as const, label: "Critical", cls: "bg-red-500" },
  { key: "high" as const, label: "High", cls: "bg-orange-500" },
  { key: "medium" as const, label: "Medium", cls: "bg-yellow-500" },
  { key: "low" as const, label: "Low", cls: "bg-blue-500" },
  { key: "info" as const, label: "Info", cls: "bg-slate-500" },
];

export default function SummaryBar({ result }: { result: ScanResult }) {
  return (
    <div className="grid grid-cols-5 gap-3">
      {items.map(({ key, label, cls }) => (
        <div key={key} className="bg-slate-800 border border-slate-700 rounded-lg p-3 text-center">
          <div className={`text-2xl font-bold ${cls.replace("bg-", "text-")}`}>{result[key]}</div>
          <div className="text-xs text-slate-400 mt-1">{label}</div>
          <div className={`h-1 rounded mt-2 ${cls} opacity-70`} />
        </div>
      ))}
    </div>
  );
}
