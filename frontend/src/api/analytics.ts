import { ApiError, apiBaseUrl, parseResponse } from "./client";

export type ProtocolTraffic = {
  protocol: string;
  packet_count: number;
  packet_percentage: number;
  total_bytes: number;
  byte_percentage: number | null;
  flow_count: number | null;
};

export type TrafficAnalytics = {
  analysis_id: number;
  original_filename: string;
  packet_count: number;
  total_bytes: number;
  flow_count: number | null;
  flow_generation_status: string;
  first_packet_timestamp: string | null;
  last_packet_timestamp: string | null;
  duration_seconds: number | null;
  timestamped_packet_count: number;
  unavailable_timestamp_packet_count: number;
  packets_per_second: number | null;
  bytes_per_second: number | null;
  forward_packets: number | null;
  backward_packets: number | null;
  forward_bytes: number | null;
  backward_bytes: number | null;
  protocols: ProtocolTraffic[];
  packet_length_distribution: { bucket: string; packet_count: number }[];
  timeline_bucket_seconds: number | null;
  timeline: {
    bucket_start_epoch: number;
    packet_count: number;
    total_bytes: number;
  }[];
  top_source_endpoints: {
    address: string;
    packet_count: number;
    total_bytes: number;
  }[];
  top_destination_endpoints: {
    address: string;
    packet_count: number;
    total_bytes: number;
  }[];
  top_flows_by_bytes: TopFlow[];
  top_flows_by_packets: TopFlow[];
};

export type TopFlow = {
  flow_id: string;
  protocol: string;
  endpoint_a: string | null;
  endpoint_b: string | null;
  total_packets: number;
  total_bytes: number;
  forward_packets: number;
  backward_packets: number;
  forward_bytes: number;
  backward_bytes: number;
  duration_seconds: number | null;
};

export type AnalysisComparison = {
  items: {
    analysis_id: number;
    original_filename: string;
    capture_format: string;
    created_at: string;
    packet_count: number;
    total_bytes: number;
    flow_count: number | null;
    protocol_distribution: ProtocolTraffic[];
    rule_findings_by_severity: Record<string, number> | null;
    rule_detection_run_id: number | null;
    ml_anomaly_count: number | null;
    ml_model_id: number | null;
    hybrid_risk_score: string | null;
    hybrid_severity: string | null;
  }[];
  metric_limitations: string[];
};

export type SecurityEvent = {
  event_id: string;
  event_type: "rule_finding" | "ml_anomaly" | "hybrid_assessment";
  analysis_id: number;
  original_filename: string;
  recorded_at: string;
  timestamp_label: string;
  severity: string | null;
  risk_score: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  protocol: string | null;
  explanation: string;
  rule_id: string | null;
  model_id: number | null;
  model_version: string | null;
  flow_id: string | null;
  related_reference: string;
};

export type SecurityEventPage = {
  items: SecurityEvent[];
  total: number;
  offset: number;
  limit: number;
};

export type SecurityEventDetail = {
  event: SecurityEvent;
  evidence: Record<string, unknown>;
  related_flow_ids: string[];
};

export type EventFilters = {
  offset?: number;
  limit?: number;
  severity?: string;
  event_type?: string;
  analysis_id?: number;
  protocol?: string;
  recorded_after?: string;
  recorded_before?: string;
};

export function getTrafficAnalytics(id: number): Promise<TrafficAnalytics> {
  return request(`/api/v1/analytics/traffic/${id}`);
}

export function compareAnalyses(ids: number[]): Promise<AnalysisComparison> {
  const query = new URLSearchParams();
  ids.forEach((id) => query.append("analysis_ids", String(id)));
  return request(`/api/v1/analytics/comparison?${query.toString()}`);
}

export function getSecurityEvents(
  filters: EventFilters,
): Promise<SecurityEventPage> {
  const query = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== "") query.set(key, String(value));
  });
  return request(`/api/v1/events?${query.toString()}`);
}

export function getSecurityEvent(id: string): Promise<SecurityEventDetail> {
  return request(`/api/v1/events/${encodeURIComponent(id)}`);
}

async function request<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`);
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
