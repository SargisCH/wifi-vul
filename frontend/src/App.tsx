import { useState } from "react";
import { runWifiScan, type ScanResult, type Severity } from "./api/scan";
import ScoreGauge from "./components/ScoreGauge";
import SummaryBar from "./components/SummaryBar";
import FindingCard from "./components/FindingCard";
import SeverityBadge from "./components/SeverityBadge";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function App() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Severity | "all">("all");

  async function handleScan() {
    setLoading(true);
    setError(null);
    try {
      const data = await runWifiScan();
      setResult(data);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unexpected error";
      const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setError(detail ?? msg);
    } finally {
      setLoading(false);
    }
  }

  const filteredFindings = result
    ? filter === "all"
      ? result.findings
      : result.findings.filter((f) => f.severity === filter)
    : [];

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">WiFi Vulnerability Scanner</h1>
          <p className="text-xs text-slate-500 mt-0.5">MikroTik security audit</p>
        </div>
        <button
          onClick={handleScan}
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold px-5 py-2 rounded-lg text-sm transition-colors flex items-center gap-2"
        >
          {loading ? (
            <>
              <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Scanning…
            </>
          ) : (
            "Run Scan"
          )}
        </button>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8 space-y-8">
        {/* Error */}
        {error && (
          <div className="bg-red-500/10 border border-red-500/40 rounded-lg px-4 py-3 text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Empty state */}
        {!result && !loading && !error && (
          <div className="text-center py-24 text-slate-500">
            <div className="text-5xl mb-4">📡</div>
            <p className="text-lg font-medium">Click "Run Scan" to analyze your MikroTik WiFi configuration</p>
            <p className="text-sm mt-2">Checks WPA version, cipher strength, MFP, passphrase quality and more</p>
          </div>
        )}

        {/* Results */}
        {result && (
          <>
            {/* Score + summary */}
            <div className="flex flex-col sm:flex-row gap-6 items-center bg-slate-800 border border-slate-700 rounded-xl p-6">
              <ScoreGauge score={result.score} />
              <div className="flex-1 w-full">
                <div className="flex items-center gap-3 mb-3 flex-wrap">
                  <span className="text-sm text-slate-400">
                    Found{" "}
                    <span className="text-slate-200 font-semibold">{result.total_findings}</span> issue
                    {result.total_findings !== 1 ? "s" : ""} across{" "}
                    <span className="text-slate-200 font-semibold">{result.interfaces.length}</span> interface
                    {result.interfaces.length !== 1 ? "s" : ""} and{" "}
                    <span className="text-slate-200 font-semibold">{result.security_profiles.length}</span> profile
                    {result.security_profiles.length !== 1 ? "s" : ""}
                  </span>
                  {result.routeros_version && (
                    <span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded">
                      RouterOS {result.routeros_version}
                    </span>
                  )}
                  <span
                    className={`text-xs font-semibold px-2 py-0.5 rounded border ${
                      result.wpa3_capable
                        ? "bg-green-500/10 text-green-400 border-green-500/30"
                        : "bg-red-500/10 text-red-400 border-red-500/30"
                    }`}
                  >
                    WPA3 {result.wpa3_capable ? "supported" : "not supported"}
                  </span>
                </div>
                <SummaryBar result={result} />
              </div>
            </div>

            {/* Filter tabs */}
            <div className="flex gap-2 flex-wrap">
              <button
                onClick={() => setFilter("all")}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  filter === "all" ? "bg-slate-600 text-white" : "bg-slate-800 text-slate-400 hover:text-slate-200"
                }`}
              >
                All ({result.total_findings})
              </button>
              {SEVERITY_ORDER.map((sev) =>
                result[sev] > 0 ? (
                  <button
                    key={sev}
                    onClick={() => setFilter(sev)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors flex items-center gap-1.5 ${
                      filter === sev ? "bg-slate-600 text-white" : "bg-slate-800 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <SeverityBadge severity={sev} />
                    <span>{result[sev]}</span>
                  </button>
                ) : null
              )}
            </div>

            {/* Findings list */}
            <div className="space-y-3">
              {filteredFindings.length === 0 ? (
                <p className="text-slate-500 text-sm text-center py-8">No findings at this severity level.</p>
              ) : (
                filteredFindings.map((f, i) => <FindingCard key={i} finding={f} />)
              )}
            </div>

            {/* Raw data */}
            <details className="bg-slate-800 border border-slate-700 rounded-lg">
              <summary className="px-4 py-3 cursor-pointer text-sm text-slate-400 hover:text-slate-200 select-none">
                Raw interface &amp; profile data
              </summary>
              <div className="px-4 pb-4 space-y-4">
                <div>
                  <h3 className="text-xs uppercase tracking-widest text-slate-500 mb-2">Wireless Interfaces</h3>
                  <pre className="text-xs text-slate-400 bg-slate-900 rounded p-3 overflow-auto max-h-60">
                    {JSON.stringify(result.interfaces, null, 2)}
                  </pre>
                </div>
                <div>
                  <h3 className="text-xs uppercase tracking-widest text-slate-500 mb-2">Security Profiles</h3>
                  <pre className="text-xs text-slate-400 bg-slate-900 rounded p-3 overflow-auto max-h-60">
                    {JSON.stringify(result.security_profiles, null, 2)}
                  </pre>
                </div>
              </div>
            </details>
          </>
        )}
      </main>
    </div>
  );
}
