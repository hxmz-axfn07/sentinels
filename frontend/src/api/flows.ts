import { ApiError, apiBaseUrl, parseResponse } from "./client";

export type NetworkFlow = {
  id: number;
  analysis_id: number;
  flow_id: string;
  ip_version: number | null;
  protocol_name: string;
  protocol_number: number | null;
  endpoint_a_ip: string | null;
  endpoint_a_port: number | null;
  endpoint_b_ip: string | null;
  endpoint_b_port: number | null;
  duration_seconds: string | null;
  total_packets: number;
  total_bytes: number;
  forward_packets: number;
  backward_packets: number;
  forward_bytes: number;
  backward_bytes: number;
  packet_length_min: number;
  packet_length_max: number;
  packet_length_mean: string;
  packet_length_stddev: string;
  interarrival_min: string | null;
  interarrival_max: string | null;
  interarrival_mean: string | null;
  interarrival_stddev: string | null;
  packets_per_second: string | null;
  bytes_per_second: string | null;
};

export type FlowList = {
  items: NetworkFlow[];
  total: number;
  offset: number;
  limit: number;
};

export type FlowGeneration = {
  analysis_id: number;
  status: "completed";
  flow_count: number;
  generated: boolean;
  flows_generated_at: string | null;
};

export async function generateFlows(
  analysisId: number,
): Promise<FlowGeneration> {
  const response = await fetch(
    `${apiBaseUrl}/api/v1/analyses/${analysisId}/flows/generate`,
    { method: "POST" },
  );
  const payload = parseResponse(await response.text());
  if (!response.ok) throw new ApiError(errorMessage(payload), response.status);
  return payload as FlowGeneration;
}

export async function getFlows(
  analysisId: number,
  offset: number,
  limit: number,
): Promise<FlowList> {
  const query = new URLSearchParams({
    offset: String(offset),
    limit: String(limit),
  });
  const response = await fetch(
    `${apiBaseUrl}/api/v1/analyses/${analysisId}/flows?${query.toString()}`,
  );
  const payload = parseResponse(await response.text());
  if (!response.ok) throw new ApiError(errorMessage(payload), response.status);
  return payload as FlowList;
}

function errorMessage(payload: unknown): string {
  if (typeof payload === "object" && payload !== null && "detail" in payload) {
    const detail = payload.detail;
    if (typeof detail === "string") return detail;
    if (typeof detail === "object" && detail !== null && "message" in detail) {
      return String(detail.message);
    }
  }
  return "The flow request could not be completed.";
}
