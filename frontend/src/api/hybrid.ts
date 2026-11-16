import { ApiError, apiBaseUrl, parseResponse } from "./client";

export type HybridSeverity =
  "informational" | "low" | "medium" | "high" | "critical";
export type HybridCorrelationLevel =
  "exact_flow" | "endpoint_pair" | "rule_only" | "ml_only" | "flow_only";
export type HybridEvidenceSource = "rule" | "ml";

export type HybridAssessment = {
  id: number;
  analysis_id: number;
  detection_run_id: number;
  model_id: number;
  model_version: string;
  scoring_config_version: string;
  scoring_config_hash: string;
  scoring_config: Record<string, unknown>;
  risk_score: string;
  severity: HybridSeverity;
  rule_evidence_count: number;
  ml_anomaly_count: number;
  correlated_evidence_count: number;
  risk_group_count: number;
  explanation: string;
  created_at: string;
  reused?: boolean;
};

export type HybridSummary = {
  analysis_id: number;
  status: "not_started" | "completed";
  assessment: HybridAssessment | null;
};

export type HybridRiskGroup = {
  id: number;
  assessment_id: number;
  analysis_id: number;
  group_key: string;
  correlation_level: HybridCorrelationLevel;
  endpoint_a_ip: string | null;
  endpoint_b_ip: string | null;
  protocol_name: string | null;
  risk_score: string;
  rule_component: string;
  ml_component: string;
  exact_flow_bonus: string;
  severity: HybridSeverity;
  rule_evidence_count: number;
  ml_anomaly_count: number;
  correlated_flow_count: number;
  explanation: string;
  created_at: string;
};

export type HybridRiskGroupList = {
  items: HybridRiskGroup[];
  total: number;
  offset: number;
  limit: number;
  assessment_id: number;
};

export type HybridEvidence = {
  id: number;
  group_id: number;
  assessment_id: number;
  analysis_id: number;
  source: HybridEvidenceSource;
  source_id: number;
  detection_finding_id: number | null;
  anomaly_result_id: number | null;
  detection_run_id: number;
  model_id: number;
  model_version: string;
  flow_id: string | null;
  rule_id: string | null;
  rule_name: string | null;
  original_severity: string | null;
  prediction: string | null;
  anomaly_score: string | null;
  evidence: Record<string, unknown>;
  created_at: string;
};

export type HybridEvidenceList = {
  items: HybridEvidence[];
  total: number;
  offset: number;
  limit: number;
  group_id: number;
};

export type HybridAssessmentList = {
  items: HybridAssessment[];
  total: number;
  offset: number;
  limit: number;
};

export async function runHybridAssessment(
  analysisId: number,
  detectionRunId: number,
  modelId: number,
): Promise<HybridAssessment> {
  return request<HybridAssessment>(
    `/api/v1/analyses/${analysisId}/hybrid/assessments`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        detection_run_id: detectionRunId,
        model_id: modelId,
      }),
    },
  );
}

export async function getHybridSummary(
  analysisId: number,
): Promise<HybridSummary> {
  return request<HybridSummary>(
    `/api/v1/analyses/${analysisId}/hybrid/summary`,
  );
}

export async function getHybridAssessments(
  analysisId: number,
  offset = 0,
  limit = 25,
  severity?: HybridSeverity,
): Promise<HybridAssessmentList> {
  return request<HybridAssessmentList>(
    `/api/v1/analyses/${analysisId}/hybrid/assessments?${query({ offset, limit, severity })}`,
  );
}

export async function getHybridGroups(
  analysisId: number,
  assessmentId: number,
  offset = 0,
  limit = 25,
  severity?: HybridSeverity,
): Promise<HybridRiskGroupList> {
  return request<HybridRiskGroupList>(
    `/api/v1/analyses/${analysisId}/hybrid/assessments/${assessmentId}/groups?${query({ offset, limit, severity })}`,
  );
}

export async function getHybridEvidence(
  analysisId: number,
  assessmentId: number,
  groupId: number,
  offset = 0,
  limit = 25,
): Promise<HybridEvidenceList> {
  return request<HybridEvidenceList>(
    `/api/v1/analyses/${analysisId}/hybrid/assessments/${assessmentId}/groups/${groupId}/evidence?${query({ offset, limit })}`,
  );
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, init);
  const payload = parseResponse(await response.text());
  if (!response.ok) throw new ApiError(errorMessage(payload), response.status);
  return payload as T;
}

function query(values: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined) params.set(key, String(value));
  }
  return params.toString();
}

function errorMessage(payload: unknown): string {
  if (typeof payload === "object" && payload !== null && "detail" in payload) {
    const detail = payload.detail;
    if (typeof detail === "string") return detail;
    if (typeof detail === "object" && detail !== null && "message" in detail) {
      return String(detail.message);
    }
  }
  return "The hybrid assessment request could not be completed.";
}
