import { ApiError, apiBaseUrl, parseResponse } from "./client";

export type PredictionLabel = "normal" | "anomaly";

export type AnomalyModel = {
  id: number;
  model_version: string;
  algorithm: string;
  feature_schema_version: string;
  feature_names: string[];
  active_feature_names: string[];
  preprocessing_config: Record<string, unknown>;
  isolation_forest_config: Record<string, unknown>;
  random_seed: number;
  training_analysis_ids: number[];
  training_sample_count: number;
  training_population_count: number;
  sklearn_version: string;
  status: "ready";
  created_at: string;
  trained_at: string;
};

export type ModelList = {
  items: AnomalyModel[];
  total: number;
  offset: number;
  limit: number;
};

export type ModelTraining = {
  analysis_ids: number[];
  n_estimators: number;
  contamination: number | "auto";
  max_samples: number | "auto";
  random_seed: number;
};

export type InferenceResult = {
  analysis_id: number;
  model_id: number;
  model_version: string;
  result_count: number;
  anomaly_count: number;
  normal_count: number;
  reused: boolean;
};

export type AnomalySummary = {
  analysis_id: number;
  model_id: number | null;
  model_version: string | null;
  status: "not_started" | "completed";
  result_count: number;
  anomaly_count: number;
  normal_count: number;
};

export type AnomalyResult = {
  id: number;
  model_id: number;
  model_version: string;
  analysis_id: number;
  flow_id: string;
  prediction: PredictionLabel;
  anomaly_score: number | string;
  created_at: string;
  flow: {
    flow_id: string;
    protocol_name: string;
    endpoint_a_ip: string | null;
    endpoint_a_port: number | null;
    endpoint_b_ip: string | null;
    endpoint_b_port: number | null;
    total_packets: number;
    total_bytes: number;
    duration_seconds: string | null;
  };
};

export type AnomalyResultList = {
  items: AnomalyResult[];
  total: number;
  offset: number;
  limit: number;
  model_id: number;
  model_version: string;
};

export async function getModels(): Promise<ModelList> {
  return request<ModelList>("/api/v1/ml/models?limit=100");
}

export async function trainModel(input: ModelTraining): Promise<AnomalyModel> {
  return request<AnomalyModel>("/api/v1/ml/models/train", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export async function runInference(
  analysisId: number,
  modelId: number,
): Promise<InferenceResult> {
  return request<InferenceResult>(
    `/api/v1/analyses/${analysisId}/ml/inference`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model_id: modelId }),
    },
  );
}

export async function getMlSummary(
  analysisId: number,
  modelId?: number,
): Promise<AnomalySummary> {
  const query = modelId === undefined ? "" : `?model_id=${modelId}`;
  return request<AnomalySummary>(
    `/api/v1/analyses/${analysisId}/ml/summary${query}`,
  );
}

export async function getAnomalyResults(
  analysisId: number,
  modelId: number,
  offset: number,
  limit: number,
  prediction?: PredictionLabel,
): Promise<AnomalyResultList> {
  const query = new URLSearchParams({
    model_id: String(modelId),
    offset: String(offset),
    limit: String(limit),
  });
  if (prediction) query.set("prediction", prediction);
  return request<AnomalyResultList>(
    `/api/v1/analyses/${analysisId}/ml/results?${query.toString()}`,
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
  return "The machine-learning request could not be completed.";
}
