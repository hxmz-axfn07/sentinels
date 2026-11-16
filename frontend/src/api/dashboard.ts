import { ApiError, apiBaseUrl, parseResponse } from "./client";

export type OverviewAnalysis = {
  id: number;
  original_filename: string;
  file_size_bytes: number;
  capture_format: string;
  status: "pending" | "processing" | "completed" | "failed";
  packet_count: number | null;
  flow_count: number | null;
  flow_generation_status: string;
  created_at: string;
  detection_status: "not_started" | "running" | "completed" | "failed";
  finding_count: number;
  ml_status: "not_started" | "completed";
  anomaly_count: number;
  hybrid_status: "not_started" | "completed";
  risk_score: string | null;
  severity: string | null;
};

export type DashboardOverview = {
  analysis_count: number;
  completed_analysis_count: number;
  packet_count: number;
  flow_count: number;
  rule_finding_count: number;
  high_priority_finding_count: number;
  rule_analysis_count: number;
  ml_anomaly_count: number;
  ml_analysis_count: number;
  hybrid_assessment_count: number;
  severity_counts: Record<string, number>;
  protocol_distribution: { protocol: string; flow_count: number }[];
  recent_analyses: OverviewAnalysis[];
  recent_high_priority_findings: {
    id: number;
    analysis_id: number;
    rule_id: string;
    rule_name: string;
    severity: "high" | "critical";
    source_ip: string | null;
    destination_ip: string | null;
    explanation: string;
    created_at: string;
  }[];
};

export type AnalysisHistory = {
  items: OverviewAnalysis[];
  total: number;
  offset: number;
  limit: number;
};

export async function getDashboardOverview(): Promise<DashboardOverview> {
  const response = await fetch(`${apiBaseUrl}/api/v1/dashboard/overview`);
  const payload = parseResponse(await response.text());
  if (!response.ok) throw new ApiError(errorMessage(payload), response.status);
  return payload as DashboardOverview;
}

export async function getAnalysisHistory(
  offset = 0,
  limit = 25,
): Promise<AnalysisHistory> {
  const response = await fetch(
    `${apiBaseUrl}/api/v1/dashboard/analyses?offset=${offset}&limit=${limit}`,
  );
  const payload = parseResponse(await response.text());
  if (!response.ok) throw new ApiError(errorMessage(payload), response.status);
  return payload as AnalysisHistory;
}

function errorMessage(payload: unknown): string {
  if (typeof payload === "object" && payload !== null && "detail" in payload) {
    const detail = payload.detail;
    if (typeof detail === "string") return detail;
    if (typeof detail === "object" && detail !== null && "message" in detail) {
      return String(detail.message);
    }
  }
  return "The dashboard overview could not be loaded.";
}
