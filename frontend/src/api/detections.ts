import { ApiError, apiBaseUrl, parseResponse } from "./client";

export type DetectionSeverity = "low" | "medium" | "high" | "critical";
export type DetectionStatus =
  "not_started" | "processing" | "completed" | "failed";

export type DetectionRun = {
  id: number;
  analysis_id: number;
  config_hash: string;
  status: Exclude<DetectionStatus, "not_started">;
  finding_count: number;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
  reused: boolean;
};

export type FlowReference = {
  id: number;
  flow_id: string;
  protocol_name: string;
  endpoint_a_ip: string | null;
  endpoint_a_port: number | null;
  endpoint_b_ip: string | null;
  endpoint_b_port: number | null;
};

export type DetectionFinding = {
  id: number;
  run_id: number;
  analysis_id: number;
  rule_id: string;
  rule_name: string;
  severity: DetectionSeverity;
  source_ip: string | null;
  destination_ip: string | null;
  protocol_name: string | null;
  explanation: string;
  evidence: Record<string, unknown>;
  supporting_flow_count: number;
  supporting_flow_sample_truncated: boolean;
  created_at: string;
  supporting_flows: FlowReference[];
};

export type FindingList = {
  items: DetectionFinding[];
  total: number;
  offset: number;
  limit: number;
  run_id: number | null;
};

export type DetectionSummary = {
  analysis_id: number;
  run_id: number | null;
  status: DetectionStatus;
  finding_count: number;
  severity_counts: Record<DetectionSeverity, number>;
  rule_counts: { rule_id: string; count: number }[];
  config_hash: string | null;
  error_message: string | null;
  created_at: string | null;
  completed_at: string | null;
};

export async function runDetection(analysisId: number): Promise<DetectionRun> {
  return request<DetectionRun>(
    `/api/v1/analyses/${analysisId}/detections/run`,
    { method: "POST" },
  );
}

export async function getDetectionSummary(
  analysisId: number,
): Promise<DetectionSummary> {
  return request<DetectionSummary>(
    `/api/v1/analyses/${analysisId}/detection-summary`,
  );
}

export async function getFindings(
  analysisId: number,
  offset: number,
  limit: number,
  severity?: DetectionSeverity,
  ruleId?: string,
): Promise<FindingList> {
  const query = new URLSearchParams({
    offset: String(offset),
    limit: String(limit),
  });
  if (severity) query.set("severity", severity);
  if (ruleId) query.set("rule_id", ruleId);
  return request<FindingList>(
    `/api/v1/analyses/${analysisId}/findings?${query.toString()}`,
  );
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, init);
  const payload = parseResponse(await response.text());
  if (!response.ok) throw new ApiError(errorMessage(payload), response.status);
  return payload as T;
}

function errorMessage(payload: unknown): string {
  if (typeof payload === "object" && payload !== null && "detail" in payload) {
    const detail = payload.detail;
    if (typeof detail === "string") return detail;
    if (typeof detail === "object" && detail !== null && "message" in detail) {
      return String(detail.message);
    }
  }
  return "The detection request could not be completed.";
}
