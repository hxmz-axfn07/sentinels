import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Analysis, Packet, PacketList } from "./api/analyses";
import type {
  DetectionFinding,
  DetectionSummary,
  FindingList,
} from "./api/detections";
import type { FlowList, NetworkFlow } from "./api/flows";
import {
  getAnalyses,
  getAnalysis,
  getPackets,
  getUploadLimits,
  uploadAnalysis,
} from "./api/analyses";
import { generateFlows, getFlows } from "./api/flows";
import { getHealth } from "./api/health";
import {
  getDetectionSummary,
  getFindings,
  runDetection,
} from "./api/detections";
import App from "./App";

vi.mock("./api/analyses", () => ({
  getAnalyses: vi.fn(),
  getAnalysis: vi.fn(),
  getPackets: vi.fn(),
  getUploadLimits: vi.fn(),
  uploadAnalysis: vi.fn(),
}));

vi.mock("./api/health", () => ({ getHealth: vi.fn() }));
vi.mock("./api/detections", () => ({
  getDetectionSummary: vi.fn(),
  getFindings: vi.fn(),
  runDetection: vi.fn(),
}));
vi.mock("./api/flows", () => ({
  generateFlows: vi.fn(),
  getFlows: vi.fn(),
}));

afterEach(cleanup);

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getHealth).mockResolvedValue({ status: "ok" });
  vi.mocked(getDetectionSummary).mockResolvedValue(detectionSummary(1));
  vi.mocked(getFindings).mockResolvedValue(findingPage([], 0));
  vi.mocked(runDetection).mockResolvedValue({
    id: 1,
    analysis_id: 1,
    config_hash: "a".repeat(64),
    status: "completed",
    finding_count: 1,
    error_message: null,
    created_at: "2026-11-15T00:00:00Z",
    completed_at: "2026-11-15T00:00:01Z",
    reused: false,
  });
  vi.mocked(getUploadLimits).mockResolvedValue({
    max_upload_size_bytes: 1024 * 1024,
  });
  vi.mocked(getAnalyses).mockResolvedValue({
    items: [],
    total: 0,
    offset: 0,
    limit: 100,
  });
  vi.mocked(getAnalysis).mockImplementation(async (id) => analysis(id));
  vi.mocked(getPackets).mockResolvedValue(packetPage([packet(1)], 1));
  vi.mocked(generateFlows).mockResolvedValue({
    analysis_id: 1,
    status: "completed",
    flow_count: 1,
    generated: true,
    flows_generated_at: "2026-11-15T00:00:00Z",
  });
  vi.mocked(getFlows).mockResolvedValue(flowPage([flow(1)], 1));
});

describe("SENTINEL PCAP analysis", () => {
  it("shows the API state and an honest empty state", async () => {
    render(<App />);

    expect(await screen.findByRole("status")).toHaveTextContent("API online");
    expect(
      await screen.findByText("No captures have been analyzed yet."),
    ).toBeInTheDocument();
  });

  it("shows upload progress, analysis details, and returned packet metadata", async () => {
    let finishUpload: ((value: Analysis) => void) | undefined;
    vi.mocked(uploadAnalysis).mockImplementation(async (_file, onProgress) => {
      onProgress(45);
      return new Promise((resolve) => {
        finishUpload = resolve;
      });
    });
    const result = analysis(4);
    vi.mocked(getPackets).mockResolvedValue(packetPage([packet(1)], 1));
    render(<App />);
    await screen.findByText("No captures have been analyzed yet.");

    fireEvent.change(screen.getByLabelText("Capture file"), {
      target: { files: [new File(["synthetic capture"], "synthetic.pcap")] },
    });
    fireEvent.submit(screen.getByLabelText("Capture file").closest("form")!);

    expect(await screen.findByText("45%")).toBeInTheDocument();
    expect(
      screen.getByRole("progressbar", { name: "Upload progress" }),
    ).toHaveAttribute("value", "45");

    await act(async () => finishUpload?.(result));

    expect(await screen.findByText("Analysis #4")).toBeInTheDocument();
    expect(screen.getByText("198.51.100.1:443")).toBeInTheDocument();
    expect(screen.getByText("TCP")).toBeInTheDocument();
  });

  it("rejects a file over the server-provided size limit before upload", async () => {
    vi.mocked(getUploadLimits).mockResolvedValue({ max_upload_size_bytes: 4 });
    render(<App />);
    await screen.findByText("Maximum size: 4 B");

    fireEvent.change(screen.getByLabelText("Capture file"), {
      target: { files: [new File(["too large"], "large.pcap")] },
    });
    fireEvent.submit(screen.getByLabelText("Capture file").closest("form")!);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "exceeds the configured upload limit",
    );
    expect(uploadAnalysis).not.toHaveBeenCalled();
  });

  it("shows server validation errors", async () => {
    vi.mocked(uploadAnalysis).mockRejectedValue(
      new Error("The file is not a supported capture."),
    );
    render(<App />);
    await screen.findByText("No captures have been analyzed yet.");
    fireEvent.change(screen.getByLabelText("Capture file"), {
      target: { files: [new File(["bad"], "bad.pcap")] },
    });
    fireEvent.submit(screen.getByLabelText("Capture file").closest("form")!);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The file is not a supported capture.",
    );
  });

  it("loads packet pages for the selected analysis", async () => {
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [analysis(8)],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getPackets).mockImplementation(async (_id, offset) =>
      offset === 0
        ? packetPage(
            Array.from({ length: 50 }, (_, index) => packet(index + 1)),
            51,
            offset,
          )
        : packetPage([packet(51)], 51, offset),
    );
    render(<App />);
    await screen.findByText("synthetic.pcap", { selector: "span" });
    fireEvent.click(screen.getByRole("button", { name: /synthetic\.pcap/ }));
    expect(await screen.findByText("192.0.2.1:1001")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Next" }));

    await waitFor(() => expect(getPackets).toHaveBeenLastCalledWith(8, 50, 50));
    expect(await screen.findByText("192.0.2.1:1051")).toBeInTheDocument();
    expect(screen.getByText("51–51 of 51")).toBeInTheDocument();
  });

  it("generates flows and displays returned directional statistics", async () => {
    const selected = analysis(12);
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [selected],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(generateFlows).mockResolvedValue({
      analysis_id: 12,
      status: "completed",
      flow_count: 1,
      generated: true,
      flows_generated_at: "2026-11-15T00:00:00Z",
    });
    vi.mocked(getFlows).mockResolvedValue(flowPage([flow(1)], 1));
    render(<App />);
    await screen.findByText("synthetic.pcap", { selector: "span" });
    fireEvent.click(screen.getByRole("button", { name: /synthetic\.pcap/ }));
    await screen.findByText("Analysis #12");
    fireEvent.click(screen.getByRole("button", { name: "Generate flows" }));

    expect(await screen.findByText("10.0.0.1:51500")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.2:443")).toBeInTheDocument();
    expect(screen.getByText("2 · 150 B")).toBeInTheDocument();
    expect(screen.getByText("1 · 80 B")).toBeInTheDocument();
    expect(generateFlows).toHaveBeenCalledWith(12);
    expect(getFlows).toHaveBeenLastCalledWith(12, 0, 50);
  });

  it("loads flow pages and reports flow-generation errors", async () => {
    const selected = {
      ...analysis(13),
      flow_generation_status: "completed" as const,
      flow_count: 51,
    };
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [selected],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getAnalysis).mockResolvedValue(selected);
    vi.mocked(getFlows)
      .mockResolvedValueOnce(
        flowPage(
          Array.from({ length: 50 }, (_, index) => flow(index + 1)),
          51,
        ),
      )
      .mockResolvedValueOnce(flowPage([flow(51)], 51, 50));
    render(<App />);
    await screen.findByText("synthetic.pcap", { selector: "span" });
    fireEvent.click(screen.getByRole("button", { name: /synthetic\.pcap/ }));
    await waitFor(() =>
      expect(screen.getAllByText("10.0.0.1:51500")).toHaveLength(50),
    );
    fireEvent.click(screen.getByRole("button", { name: "Next flows" }));

    await waitFor(() => expect(getFlows).toHaveBeenLastCalledWith(13, 50, 50));
    expect(await screen.findByText("51–51 of 51")).toBeInTheDocument();
  });

  it("shows flow-generation errors", async () => {
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [analysis(14)],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(generateFlows).mockRejectedValue(
      new Error("Flow generation failed."),
    );
    render(<App />);
    await screen.findByText("synthetic.pcap", { selector: "span" });
    fireEvent.click(screen.getByRole("button", { name: /synthetic\.pcap/ }));
    await screen.findByText("Analysis #14");
    fireEvent.click(screen.getByRole("button", { name: "Generate flows" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Flow generation failed.",
    );
  });

  it("runs detection and displays real finding evidence and severity counts", async () => {
    const selected = {
      ...analysis(21),
      flow_generation_status: "completed" as const,
      flow_count: 6,
    };
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [selected],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getAnalysis).mockResolvedValue(selected);
    vi.mocked(getDetectionSummary).mockResolvedValueOnce(detectionSummary(21));
    vi.mocked(runDetection).mockResolvedValue({
      id: 7,
      analysis_id: 21,
      config_hash: "b".repeat(64),
      status: "completed",
      finding_count: 1,
      error_message: null,
      created_at: "2026-11-15T00:00:00Z",
      completed_at: "2026-11-15T00:00:01Z",
      reused: false,
    });
    vi.mocked(getDetectionSummary).mockResolvedValueOnce({
      ...detectionSummary(21),
      run_id: 7,
      status: "completed",
      finding_count: 1,
      severity_counts: { low: 0, medium: 0, high: 1, critical: 0 },
      rule_counts: [{ rule_id: "PORT_SCAN", count: 1 }],
    });
    vi.mocked(getFindings).mockResolvedValue(findingPage([finding(21)], 1));

    render(<App />);
    await screen.findByText("synthetic.pcap", { selector: "span" });
    fireEvent.click(screen.getByRole("button", { name: /synthetic\.pcap/ }));
    await screen.findByText("Run detection");
    await waitFor(() => expect(getDetectionSummary).toHaveBeenCalledWith(21));
    fireEvent.click(screen.getByRole("button", { name: "Run detection" }));

    expect(
      await screen.findByRole("heading", { name: "Multi-port probing" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/source contacted 12 distinct destination ports/i),
    ).toBeInTheDocument();
    expect(screen.getByText("high: 1")).toBeInTheDocument();
    expect(runDetection).toHaveBeenCalledWith(21);
    expect(getFindings).toHaveBeenCalledWith(21, 0, 25, undefined, undefined);
  });

  it("filters and paginates findings through the API", async () => {
    const selected = {
      ...analysis(22),
      flow_generation_status: "completed" as const,
      flow_count: 10,
    };
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [selected],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getAnalysis).mockResolvedValue(selected);
    vi.mocked(getDetectionSummary).mockResolvedValue({
      ...detectionSummary(22),
      status: "completed",
      finding_count: 26,
    });
    vi.mocked(getFindings)
      .mockResolvedValueOnce(
        findingPage(
          Array.from({ length: 25 }, (_, i) => finding(i + 1)),
          26,
        ),
      )
      .mockResolvedValueOnce(findingPage([finding(26)], 26, 25))
      .mockResolvedValueOnce(findingPage([finding(26)], 1));

    render(<App />);
    await screen.findByText("synthetic.pcap", { selector: "span" });
    fireEvent.click(screen.getByRole("button", { name: /synthetic\.pcap/ }));
    expect(await screen.findByText("1–25 of 26")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next findings" }));
    await waitFor(() =>
      expect(getFindings).toHaveBeenLastCalledWith(
        22,
        25,
        25,
        undefined,
        undefined,
      ),
    );
    fireEvent.change(screen.getByLabelText("Filter findings by severity"), {
      target: { value: "critical" },
    });
    await waitFor(() =>
      expect(getFindings).toHaveBeenLastCalledWith(
        22,
        0,
        25,
        "critical",
        undefined,
      ),
    );
  });

  it("shows detection errors and not-started empty state", async () => {
    const selected = {
      ...analysis(23),
      flow_generation_status: "completed" as const,
      flow_count: 1,
    };
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [selected],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getAnalysis).mockResolvedValue(selected);
    vi.mocked(runDetection).mockRejectedValue(
      new Error("Detection did not complete."),
    );
    render(<App />);
    await screen.findByText("synthetic.pcap", { selector: "span" });
    fireEvent.click(screen.getByRole("button", { name: /synthetic\.pcap/ }));
    await screen.findByText("Run detection");
    fireEvent.click(screen.getByRole("button", { name: "Run detection" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Detection did not complete.",
    );
    expect(
      screen.getByText("Run detection after flow generation has completed."),
    ).toBeInTheDocument();
  });

  it("shows a detection loading state until the API returns", async () => {
    const selected = {
      ...analysis(24),
      flow_generation_status: "completed" as const,
      flow_count: 1,
    };
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [selected],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getAnalysis).mockResolvedValue(selected);
    let finishRun: (() => void) | undefined;
    vi.mocked(runDetection).mockImplementation(
      () =>
        new Promise((resolve) => {
          finishRun = () =>
            resolve({
              id: 9,
              analysis_id: 24,
              config_hash: "c".repeat(64),
              status: "completed",
              finding_count: 0,
              error_message: null,
              created_at: "2026-11-15T00:00:00Z",
              completed_at: "2026-11-15T00:00:01Z",
              reused: false,
            });
        }),
    );

    render(<App />);
    await screen.findByText("synthetic.pcap", { selector: "span" });
    fireEvent.click(screen.getByRole("button", { name: /synthetic\.pcap/ }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Run detection" }),
    );
    expect(
      screen.getByRole("button", { name: "Running detection…" }),
    ).toBeDisabled();

    await act(async () => finishRun?.());
  });
});

function analysis(id: number): Analysis {
  return {
    id,
    original_filename: "synthetic.pcap",
    storage_key: `generated-${id}.pcap`,
    file_size_bytes: 1024,
    capture_format: "pcap",
    status: "completed",
    packet_count: 1,
    error_message: null,
    created_at: "2026-11-14T00:00:00Z",
    completed_at: "2026-11-14T00:00:01Z",
    flow_generation_status: "not_started",
    flow_count: 0,
    flow_error_message: null,
    flows_generated_at: null,
  };
}

function packet(index: number): Packet {
  return {
    id: index,
    packet_index: index,
    timestamp: "1700000000.123456789",
    source_ip: "192.0.2.1",
    destination_ip: "198.51.100.1",
    source_port: 1000 + index,
    destination_port: 443,
    network_protocol: "IPv4",
    transport_protocol: "TCP",
    ip_protocol_number: 6,
    packet_length: 64,
    tcp_flags: 2,
    icmp_type: null,
    icmp_code: null,
  };
}

function packetPage(items: Packet[], total: number, offset = 0): PacketList {
  return { items, total, offset, limit: 50 };
}

function flow(index: number): NetworkFlow {
  return {
    id: index,
    analysis_id: 12,
    flow_id: index.toString(16).padStart(64, "0"),
    ip_version: 4,
    protocol_name: "TCP",
    protocol_number: 6,
    endpoint_a_ip: "10.0.0.1",
    endpoint_a_port: 51500,
    endpoint_b_ip: "10.0.0.2",
    endpoint_b_port: 443,
    duration_seconds: "1.000000000",
    total_packets: 3,
    total_bytes: 230,
    forward_packets: 2,
    backward_packets: 1,
    forward_bytes: 150,
    backward_bytes: 80,
    packet_length_min: 60,
    packet_length_max: 90,
    packet_length_mean: "76.666666667",
    packet_length_stddev: "12.472191289",
    interarrival_min: "0.500000000",
    interarrival_max: "0.500000000",
    interarrival_mean: "0.500000000",
    interarrival_stddev: "0.000000000",
    packets_per_second: "3.000000000",
    bytes_per_second: "230.000000000",
  };
}

function flowPage(items: NetworkFlow[], total: number, offset = 0): FlowList {
  return { items, total, offset, limit: 50 };
}

function detectionSummary(analysisId: number): DetectionSummary {
  return {
    analysis_id: analysisId,
    run_id: null,
    status: "not_started",
    finding_count: 0,
    severity_counts: { low: 0, medium: 0, high: 0, critical: 0 },
    rule_counts: [],
    config_hash: null,
    error_message: null,
    created_at: null,
    completed_at: null,
  };
}

function finding(id: number): DetectionFinding {
  return {
    id,
    run_id: 7,
    analysis_id: 21,
    rule_id: "PORT_SCAN",
    rule_name: "Multi-port probing",
    severity: "high",
    source_ip: "192.0.2.10",
    destination_ip: "198.51.100.20",
    protocol_name: "TCP/UDP",
    explanation:
      "The source contacted 12 distinct destination ports on one target in this capture.",
    evidence: { distinct_destination_port_count: 12, flow_count: 12 },
    supporting_flow_count: 12,
    supporting_flow_sample_truncated: false,
    created_at: "2026-11-15T00:00:01Z",
    supporting_flows: [],
  };
}

function findingPage(
  items: DetectionFinding[],
  total: number,
  offset = 0,
): FindingList {
  return { items, total, offset, limit: 25, run_id: items[0]?.run_id ?? null };
}
