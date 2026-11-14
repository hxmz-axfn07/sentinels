import { ApiError, apiBaseUrl, parseResponse } from "./client";

export type AnalysisStatus = "pending" | "processing" | "completed" | "failed";

export type Analysis = {
  id: number;
  original_filename: string;
  storage_key: string | null;
  file_size_bytes: number;
  capture_format: string;
  status: AnalysisStatus;
  packet_count: number;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
};

export type AnalysisList = {
  items: Analysis[];
  total: number;
  offset: number;
  limit: number;
};

export type Packet = {
  id: number;
  packet_index: number;
  timestamp: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  network_protocol: string;
  transport_protocol: string | null;
  ip_protocol_number: number | null;
  packet_length: number;
  tcp_flags: number | null;
  icmp_type: number | null;
  icmp_code: number | null;
};

export type PacketList = {
  items: Packet[];
  total: number;
  offset: number;
  limit: number;
};

export type UploadLimits = { max_upload_size_bytes: number };

export async function getUploadLimits(): Promise<UploadLimits> {
  return request<UploadLimits>("/api/v1/analyses/limits");
}

export async function getAnalyses(): Promise<AnalysisList> {
  return request<AnalysisList>("/api/v1/analyses?limit=100");
}

export async function getAnalysis(id: number): Promise<Analysis> {
  return request<Analysis>(`/api/v1/analyses/${id}`);
}

export async function getPackets(
  id: number,
  offset: number,
  limit: number,
): Promise<PacketList> {
  return request<PacketList>(
    `/api/v1/analyses/${id}/packets?offset=${offset}&limit=${limit}`,
  );
}

export function uploadAnalysis(
  file: File,
  onProgress: (percent: number) => void,
): Promise<Analysis> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${apiBaseUrl}/api/v1/analyses/upload`);
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    });
    xhr.addEventListener("load", () => {
      const payload = parseResponse(xhr.responseText);
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(payload as Analysis);
      } else {
        reject(new ApiError(errorMessage(payload), xhr.status));
      }
    });
    xhr.addEventListener("error", () =>
      reject(new ApiError("Could not reach the API.")),
    );
    const form = new FormData();
    form.append("file", file);
    xhr.send(form);
  });
}

async function request<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`);
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
  return "The request could not be completed.";
}
