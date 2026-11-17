import { ApiError, apiBaseUrl, parseResponse } from "./client";

export type IncidentStatus =
  "open" | "acknowledged" | "investigating" | "resolved" | "closed";
export type IncidentPriority = "low" | "medium" | "high" | "critical";

export type IncidentEvidence = {
  id: number;
  event_id: string;
  source_type: "rule_finding" | "ml_anomaly" | "hybrid_assessment";
  source_id: number;
  analysis_id: number;
  original_filename: string;
  severity: string | null;
  anomaly_score: string | null;
  risk_score: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  protocol: string | null;
  explanation: string;
  flow_ids: string[];
  model_id: number | null;
  model_version: string | null;
  evidence: Record<string, unknown>;
  attached_at: string;
};

export type Incident = {
  id: number;
  title: string;
  description: string;
  status: IncidentStatus;
  priority: IncidentPriority;
  created_by: string | null;
  assigned_to: string | null;
  resolution_summary: string | null;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
  evidence_count: number;
  analysis_ids: number[];
};

export type IncidentDetail = Incident & {
  evidence: IncidentEvidence[];
  notes: {
    id: number;
    body: string;
    created_by: string | null;
    created_at: string;
  }[];
  history: {
    id: number;
    action: string;
    details: Record<string, unknown>;
    actor: string | null;
    created_at: string;
  }[];
  local_single_user: boolean;
};

export type IncidentPage = {
  items: Incident[];
  total: number;
  offset: number;
  limit: number;
};
export type IncidentSummary = {
  total: number;
  status_counts: Record<string, number>;
  priority_counts: Record<string, number>;
};

export function getIncidents(
  filters: {
    offset?: number;
    status?: string;
    priority?: string;
    search?: string;
  } = {},
) {
  const query = new URLSearchParams();
  Object.entries(filters).forEach(
    ([key, value]) => value && query.set(key, String(value)),
  );
  return request<IncidentPage>(`/api/v1/incidents?${query}`);
}
export function getIncidentSummary() {
  return request<IncidentSummary>("/api/v1/incidents/summary");
}
export function getIncident(id: number) {
  return request<IncidentDetail>(`/api/v1/incidents/${id}`);
}
export function createIncident(data: {
  title: string;
  description: string;
  priority: IncidentPriority;
  event_ids: string[];
}) {
  return request<IncidentDetail>("/api/v1/incidents", {
    method: "POST",
    body: JSON.stringify(data),
  });
}
export function updateIncident(
  id: number,
  data: Partial<Pick<Incident, "title" | "description" | "priority">>,
) {
  return request<IncidentDetail>(`/api/v1/incidents/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}
export function updateIncidentStatus(
  id: number,
  status: IncidentStatus,
  resolution_summary?: string,
) {
  return request<IncidentDetail>(`/api/v1/incidents/${id}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status, resolution_summary }),
  });
}
export function attachEvidence(id: number, event_ids: string[]) {
  return request<IncidentDetail>(`/api/v1/incidents/${id}/evidence`, {
    method: "POST",
    body: JSON.stringify({ event_ids }),
  });
}
export function detachEvidence(id: number, evidenceId: number) {
  return request<void>(`/api/v1/incidents/${id}/evidence/${evidenceId}`, {
    method: "DELETE",
  });
}
export function addIncidentNote(id: number, body: string) {
  return request<IncidentDetail>(`/api/v1/incidents/${id}/notes`, {
    method: "POST",
    body: JSON.stringify({ body }),
  }).then(() => getIncident(id));
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init.headers },
  });
  const payload = parseResponse(await response.text());
  if (!response.ok) {
    const detail =
      typeof payload === "object" && payload !== null && "detail" in payload
        ? payload.detail
        : null;
    throw new ApiError(
      typeof detail === "string"
        ? detail
        : "The request could not be completed.",
      response.status,
    );
  }
  return payload as T;
}
