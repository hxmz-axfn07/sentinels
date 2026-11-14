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
import {
  getAnalyses,
  getAnalysis,
  getPackets,
  getUploadLimits,
  uploadAnalysis,
} from "./api/analyses";
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
