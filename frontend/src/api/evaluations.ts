import { ApiError, apiBaseUrl, parseResponse } from "./client";

export type EvaluationRun = {
  id: number;
  dataset_version: string;
  random_seed: number;
  repeat_count: number;
  status: "running" | "completed" | "failed";
  failure_summary: string | null;
  results: Record<string, unknown> | null;
  started_at: string;
  completed_at: string | null;
  created_at: string;
};

export type EvaluationRunSummary = Omit<EvaluationRun, "results">;

export type EvaluationList = {
  items: EvaluationRunSummary[];
  total: number;
  offset: number;
  limit: number;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  const body = parseResponse(await response.text()) as
    (T & { detail?: unknown }) | null;
  if (!response.ok) {
    const message =
      body && typeof body.detail === "string"
        ? body.detail
        : `Evaluation request failed (${response.status}).`;
    throw new ApiError(message, response.status);
  }
  if (!body)
    throw new ApiError("The evaluation API returned an invalid response.");
  return body;
}

export function getEvaluations(offset = 0) {
  return request<EvaluationList>(
    `/api/v1/evaluations?offset=${offset}&limit=20`,
  );
}

export function getEvaluation(id: number) {
  return request<EvaluationRun>(`/api/v1/evaluations/${id}`);
}

export function createEvaluation(randomSeed = 1101, repeatCount = 3) {
  return request<EvaluationRun>("/api/v1/evaluations", {
    method: "POST",
    body: JSON.stringify({
      random_seed: randomSeed,
      repeat_count: repeatCount,
    }),
  });
}
