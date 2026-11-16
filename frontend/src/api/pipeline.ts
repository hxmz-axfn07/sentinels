import { ApiError, apiBaseUrl, parseResponse } from "./client";
import type { HybridSeverity } from "./hybrid";

export type PipelineStageName = "flows" | "detection" | "inference" | "hybrid";
export type PipelineStageStatus =
  "pending" | "running" | "completed" | "skipped" | "failed";
export type PipelineStatus = "running" | "completed" | "failed";

export type PipelineStageExecution = {
  id: number;
  run_id: number;
  analysis_id: number;
  stage: PipelineStageName;
  execution_order: number;
  requested: boolean;
  status: PipelineStageStatus;
  reused: boolean;
  result_summary: Record<string, unknown> | null;
  error_summary: string | null;
  started_at: string | null;
  completed_at: string | null;
};

export type PipelineRun = {
  id: number;
  analysis_id: number;
  pipeline_version: string;
  requested_stages: PipelineStageName[];
  model_id: number | null;
  model_version: string | null;
  detection_run_id: number | null;
  hybrid_assessment_id: number | null;
  status: PipelineStatus;
  failure_summary: string | null;
  started_at: string;
  completed_at: string | null;
  created_at: string;
  stages: PipelineStageExecution[];
  risk_score: string | null;
  severity: HybridSeverity | null;
  reused_run: boolean;
};

export type PipelineSummary = {
  analysis_id: number;
  status: "not_started" | PipelineStatus;
  latest_run: PipelineRun | null;
};

export type PipelineRunList = {
  items: PipelineRun[];
  total: number;
  offset: number;
  limit: number;
};

export async function startPipeline(
  analysisId: number,
  stages: PipelineStageName[],
  modelId?: number,
  detectionRunId?: number,
): Promise<PipelineRun> {
  return request<PipelineRun>(`/api/v1/analyses/${analysisId}/pipeline/runs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      stages,
      ...(modelId === undefined ? {} : { model_id: modelId }),
      ...(detectionRunId === undefined
        ? {}
        : { detection_run_id: detectionRunId }),
    }),
  });
}

export async function getPipelineSummary(
  analysisId: number,
): Promise<PipelineSummary> {
  return request<PipelineSummary>(
    `/api/v1/analyses/${analysisId}/pipeline/summary`,
  );
}

export async function getPipelineRuns(
  analysisId: number,
  offset = 0,
  limit = 20,
): Promise<PipelineRunList> {
  const query = new URLSearchParams({
    offset: String(offset),
    limit: String(limit),
  });
  return request<PipelineRunList>(
    `/api/v1/analyses/${analysisId}/pipeline/runs?${query}`,
  );
}

export async function getPipelineRun(
  analysisId: number,
  runId: number,
): Promise<PipelineRun> {
  return request<PipelineRun>(
    `/api/v1/analyses/${analysisId}/pipeline/runs/${runId}`,
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
  return "The analysis pipeline request could not be completed.";
}
