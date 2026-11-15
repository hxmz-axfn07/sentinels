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
import App from "./App";

vi.mock("./api/analyses", () => ({
  getAnalyses: vi.fn(),
  getAnalysis: vi.fn(),
  getPackets: vi.fn(),
  getUploadLimits: vi.fn(),
  uploadAnalysis: vi.fn(),
}));

vi.mock("./api/health", () => ({ getHealth: vi.fn() }));
vi.mock("./api/flows", () => ({
  generateFlows: vi.fn(),
  getFlows: vi.fn(),
}));

afterEach(cleanup);

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getHealth).mockResolvedValue({ status: "ok" });
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
