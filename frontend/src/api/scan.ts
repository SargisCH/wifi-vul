import axios from "axios";

const BASE = "http://localhost:8000";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  interface: string | null;
  profile: string | null;
}

export interface ScanResult {
  score: number;
  findings: Finding[];
  interfaces: Record<string, string>[];
  security_profiles: Record<string, string>[];
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  routeros_version: string;
  wpa3_capable: boolean;
}

export async function runWifiScan(): Promise<ScanResult> {
  const { data } = await axios.get<ScanResult>(`${BASE}/api/scan/wifi`);
  return data;
}
