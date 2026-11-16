import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import MonitoringAnalytics from "./MonitoringAnalytics";
import type { OverviewAnalysis } from "../api/dashboard";

const analyses: OverviewAnalysis[] = [
  {
    id: 1,
    original_filename: "SYNTHETIC-analytics.pcap",
    file_size_bytes: 300,
    capture_format: "pcap",
    status: "completed",
    packet_count: 4,
    flow_count: 2,
    flow_generation_status: "completed",
    created_at: "2026-11-15T00:00:00Z",
    detection_status: "completed",
    finding_count: 1,
    ml_status: "completed",
    anomaly_count: 1,
    hybrid_status: "completed",
    risk_score: "61.00",
    severity: "high",
  },
  {
    ...({
      id: 2,
      original_filename: "SYNTHETIC-empty.pcapng",
      file_size_bytes: 0,
      capture_format: "pcapng",
      status: "completed",
      packet_count: 0,
      flow_count: null,
      flow_generation_status: "not_started",
      created_at: "2026-11-16T00:00:00Z",
      detection_status: "not_started",
      finding_count: 0,
      ml_status: "not_started",
      anomaly_count: 0,
      hybrid_status: "not_started",
      risk_score: null,
      severity: null,
    } satisfies OverviewAnalysis),
  },
];

const traffic = {
  analysis_id: 1,
  original_filename: "SYNTHETIC-analytics.pcap",
  packet_count: 4,
  total_bytes: 420,
  flow_count: 2,
  flow_generation_status: "completed",
  first_packet_timestamp: "1970-01-01T00:01:40Z",
  last_packet_timestamp: "1970-01-01T00:01:44Z",
  duration_seconds: 4,
  timestamped_packet_count: 3,
  unavailable_timestamp_packet_count: 1,
  packets_per_second: null,
  bytes_per_second: null,
  forward_packets: 3,
  backward_packets: 1,
  forward_bytes: 300,
  backward_bytes: 120,
  protocols: [
    {
      protocol: "TCP",
      packet_count: 2,
      packet_percentage: 50,
      total_bytes: 220,
      byte_percentage: 52.38,
      flow_count: 1,
    },
  ],
  packet_length_distribution: [{ bucket: "64–127 B", packet_count: 4 }],
  timeline_bucket_seconds: 1,
  timeline: [{ bucket_start_epoch: 100, packet_count: 2, total_bytes: 220 }],
  top_source_endpoints: [
    { address: "192.0.2.10", packet_count: 4, total_bytes: 420 },
  ],
  top_destination_endpoints: [
    { address: "198.51.100.20", packet_count: 4, total_bytes: 420 },
  ],
  top_flows_by_bytes: [
    {
      flow_id: "a".repeat(64),
      protocol: "TCP",
      endpoint_a: "192.0.2.10:51500",
      endpoint_b: "198.51.100.20:443",
      total_packets: 3,
      total_bytes: 300,
      forward_packets: 2,
      backward_packets: 1,
      forward_bytes: 200,
      backward_bytes: 100,
      duration_seconds: 4,
    },
  ],
  top_flows_by_packets: [],
};

const event = {
  event_id: "rule_finding:1",
  event_type: "rule_finding",
  analysis_id: 1,
  original_filename: "SYNTHETIC-analytics.pcap",
  recorded_at: "2026-11-15T00:00:00Z",
  timestamp_label: "finding recorded",
  severity: "high",
  risk_score: null,
  source_ip: "192.0.2.10",
  destination_ip: "198.51.100.20",
  protocol: "TCP",
  explanation: "Synthetic port activity evidence.",
  rule_id: "PORT_SCAN",
  model_id: null,
  model_version: null,
  flow_id: null,
  related_reference: "rule_finding:1",
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function stubResizeObserver() {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
}

describe("MonitoringAnalytics", () => {
  it("renders API-backed protocol and timeline data and inspects event evidence", async () => {
    stubResizeObserver();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const body = url.includes("/traffic/")
        ? traffic
        : url.endsWith("/events/rule_finding%3A1")
          ? {
              event,
              evidence: { distinct_ports: 8 },
              related_flow_ids: ["a".repeat(64)],
            }
          : { items: [event], total: 1, offset: 0, limit: 20 };
      return new Response(JSON.stringify(body), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MonitoringAnalytics
        analyses={analyses}
        selectedAnalysis={analyses[0]}
        onOpenAnalysis={vi.fn()}
      />,
    );

    expect(
      await screen.findByText("Protocol distribution"),
    ).toBeInTheDocument();
    expect(screen.getByText("TCP: 2 · 50.0%")).toBeInTheDocument();
    expect(screen.getByText(/1 packets have no timestamp/)).toBeInTheDocument();
    expect(
      await screen.findByText("Synthetic port activity evidence."),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    expect(await screen.findByText(/"distinct_ports": 8/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Events recorded from"), {
      target: { value: "2026-11-15T10:00" },
    });
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(([url]) => {
          const query = new URL(String(url), "http://localhost").searchParams;
          return (
            query.get("recorded_after") ===
            new Date("2026-11-15T10:00").toISOString()
          );
        }),
      ).toBe(true),
    );
  });

  it("applies severity filters and compares selected analyses with missing stages", async () => {
    stubResizeObserver();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/traffic/"))
        return new Response(JSON.stringify(traffic), { status: 200 });
      if (url.includes("/comparison")) {
        return new Response(
          JSON.stringify({
            items: [
              {
                analysis_id: 1,
                original_filename: "SYNTHETIC-analytics.pcap",
                capture_format: "pcap",
                created_at: analyses[0].created_at,
                packet_count: 4,
                total_bytes: 420,
                flow_count: 2,
                protocol_distribution: [],
                rule_findings_by_severity: { high: 1 },
                rule_detection_run_id: 3,
                ml_anomaly_count: 1,
                ml_model_id: 1,
                hybrid_risk_score: "61.00",
                hybrid_severity: "high",
              },
              {
                analysis_id: 2,
                original_filename: "SYNTHETIC-empty.pcapng",
                capture_format: "pcapng",
                created_at: analyses[1].created_at,
                packet_count: 0,
                total_bytes: 0,
                flow_count: null,
                protocol_distribution: [],
                rule_findings_by_severity: null,
                rule_detection_run_id: null,
                ml_anomaly_count: null,
                ml_model_id: null,
                hybrid_risk_score: null,
                hybrid_severity: null,
              },
            ],
            metric_limitations: ["Missing stages remain null."],
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({ items: [event], total: 1, offset: 0, limit: 20 }),
        { status: 200 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MonitoringAnalytics
        analyses={analyses}
        selectedAnalysis={analyses[0]}
        onOpenAnalysis={vi.fn()}
      />,
    );
    const severityFilter = screen.getByLabelText("Severity");
    fireEvent.change(severityFilter, { target: { value: "high" } });
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(([url]) =>
          String(url).includes("severity=high"),
        ),
      ).toBe(true),
    );
    fireEvent.click(screen.getByRole("checkbox", { name: /#1/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /#2/ }));
    fireEvent.click(screen.getByRole("button", { name: "Compare selected" }));
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(([url]) =>
          String(url).includes("/comparison"),
        ),
      ).toBe(true),
    );
    expect(
      await screen.findByText(/Missing stages remain null\./),
    ).toBeInTheDocument();
    expect(screen.getByText("Not generated")).toBeInTheDocument();
    expect(screen.getByText("Not assessed")).toBeInTheDocument();
  });

  it("shows loading errors and empty event responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ items: [], total: 0, offset: 0, limit: 20 }),
            { status: 200 },
          ),
      ),
    );
    render(
      <MonitoringAnalytics
        analyses={[]}
        selectedAnalysis={null}
        onOpenAnalysis={vi.fn()}
      />,
    );
    expect(
      await screen.findByText(
        "No persisted security events match these filters.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Select a completed analysis to view its capture data."),
    ).toBeInTheDocument();
  });

  it("shows server errors in an accessible event alert", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ detail: "Synthetic API unavailable." }),
            {
              status: 503,
            },
          ),
      ),
    );
    render(
      <MonitoringAnalytics
        analyses={[]}
        selectedAnalysis={null}
        onOpenAnalysis={vi.fn()}
      />,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Synthetic API unavailable.",
    );
  });
});
