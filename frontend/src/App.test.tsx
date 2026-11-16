import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import type { Analysis, Packet, PacketList } from "./api/analyses";
import type {
  DetectionFinding,
  DetectionSummary,
  FindingList,
} from "./api/detections";
import type { FlowList, NetworkFlow } from "./api/flows";
import type { AnomalyModel, AnomalyResultList, AnomalySummary } from "./api/ml";
import type { HybridSummary } from "./api/hybrid";
import type { DashboardOverview, OverviewAnalysis } from "./api/dashboard";
import { getAnalysisHistory, getDashboardOverview } from "./api/dashboard";
import {
  compareAnalyses,
  getSecurityEvent,
  getSecurityEvents,
  getTrafficAnalytics,
  type SecurityEvent,
  type TrafficAnalytics,
} from "./api/analytics";
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
  getHybridEvidence,
  getHybridGroups,
  getHybridSummary,
  runHybridAssessment,
} from "./api/hybrid";
import {
  getAnomalyResults,
  getMlSummary,
  getModels,
  runInference,
  trainModel,
} from "./api/ml";
import {
  getDetectionSummary,
  getFindings,
  runDetection,
} from "./api/detections";
import { getPipelineSummary, startPipeline } from "./api/pipeline";
import App, { SentinelApplication } from "./App";

vi.mock("./api/analyses", () => ({
  getAnalyses: vi.fn(),
  getAnalysis: vi.fn(),
  getPackets: vi.fn(),
  getUploadLimits: vi.fn(),
  uploadAnalysis: vi.fn(),
}));

vi.mock("./api/health", () => ({ getHealth: vi.fn() }));
vi.mock("./api/dashboard", () => ({
  getAnalysisHistory: vi.fn(),
  getDashboardOverview: vi.fn(),
}));
vi.mock("./api/analytics", () => ({
  compareAnalyses: vi.fn(),
  getSecurityEvent: vi.fn(),
  getSecurityEvents: vi.fn(),
  getTrafficAnalytics: vi.fn(),
}));
vi.mock("./api/hybrid", () => ({
  getHybridEvidence: vi.fn(),
  getHybridGroups: vi.fn(),
  getHybridSummary: vi.fn(),
  runHybridAssessment: vi.fn(),
}));
vi.mock("./api/detections", () => ({
  getDetectionSummary: vi.fn(),
  getFindings: vi.fn(),
  runDetection: vi.fn(),
}));
vi.mock("./api/flows", () => ({
  generateFlows: vi.fn(),
  getFlows: vi.fn(),
}));
vi.mock("./api/ml", () => ({
  getAnomalyResults: vi.fn(),
  getMlSummary: vi.fn(),
  getModels: vi.fn(),
  runInference: vi.fn(),
  trainModel: vi.fn(),
}));
vi.mock("./api/pipeline", () => ({
  getPipelineSummary: vi.fn(),
  getPipelineRuns: vi.fn(),
  getPipelineRun: vi.fn(),
  startPipeline: vi.fn(),
}));

afterEach(cleanup);

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getHealth).mockResolvedValue({ status: "ok" });
  vi.mocked(getTrafficAnalytics).mockResolvedValue(syntheticTrafficAnalytics());
  vi.mocked(getSecurityEvents).mockResolvedValue({
    items: [],
    total: 0,
    offset: 0,
    limit: 20,
  });
  vi.mocked(compareAnalyses).mockResolvedValue({
    items: [],
    metric_limitations: [],
  });
  vi.mocked(getSecurityEvent).mockResolvedValue({
    event: syntheticSecurityEvent(),
    evidence: {},
    related_flow_ids: [],
  });
  vi.mocked(getDashboardOverview).mockResolvedValue(dashboardOverview());
  vi.mocked(getAnalysisHistory).mockResolvedValue({
    items: [],
    total: 0,
    offset: 0,
    limit: 25,
  });
  vi.mocked(getHybridSummary).mockImplementation(async (analysisId) =>
    hybridSummary(analysisId),
  );
  vi.mocked(getHybridGroups).mockResolvedValue({
    items: [],
    total: 0,
    offset: 0,
    limit: 10,
    assessment_id: 1,
  });
  vi.mocked(getHybridEvidence).mockResolvedValue({
    items: [],
    total: 0,
    offset: 0,
    limit: 25,
    group_id: 1,
  });
  vi.mocked(runHybridAssessment).mockResolvedValue({
    id: 1,
    analysis_id: 1,
    detection_run_id: 1,
    model_id: 1,
    model_version: "synthetic-model-version",
    scoring_config_version: "hybrid-v1",
    scoring_config_hash: "c".repeat(64),
    scoring_config: {},
    risk_score: "0.00",
    severity: "informational",
    rule_evidence_count: 0,
    ml_anomaly_count: 0,
    correlated_evidence_count: 0,
    risk_group_count: 0,
    explanation: "Synthetic no-indicator result.",
    created_at: "2026-11-16T00:00:00Z",
  });
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
  vi.mocked(getAnalysisHistory).mockImplementation(
    async (offset = 0, limit = 25) => {
      const page = await getAnalyses(offset, limit);
      return {
        items: page.items.map(historyAnalysis),
        total: page.total,
        offset,
        limit,
      };
    },
  );
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
  vi.mocked(getModels).mockResolvedValue({
    items: [],
    total: 0,
    offset: 0,
    limit: 100,
  });
  vi.mocked(getMlSummary).mockImplementation(async (analysisId, modelId) =>
    mlSummary(analysisId, modelId),
  );
  vi.mocked(getPipelineSummary).mockImplementation(async (analysisId) => ({
    analysis_id: analysisId,
    status: "not_started",
    latest_run: null,
  }));
  vi.mocked(startPipeline).mockRejectedValue(
    new Error("Pipeline not configured"),
  );
  vi.mocked(getAnomalyResults).mockResolvedValue(anomalyPage([], 0));
  vi.mocked(trainModel).mockResolvedValue(anomalyModel(1));
  vi.mocked(runInference).mockResolvedValue({
    analysis_id: 1,
    model_id: 1,
    model_version: "synthetic-model-version",
    result_count: 1,
    anomaly_count: 1,
    normal_count: 0,
    reused: false,
  });
});

describe("SENTINEL PCAP analysis", () => {
  it("updates routes, active navigation, and browser history", async () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <SentinelApplication />
        <HistoryControls />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByRole("link", { name: "Upload" }));
    expect(
      await screen.findByRole("heading", { name: "PCAP ingestion" }),
    ).toBeInTheDocument();
    expect(screen.getByTestId("current-path")).toHaveTextContent("/upload");
    expect(screen.getByRole("link", { name: "Upload" })).toHaveAttribute(
      "aria-current",
      "page",
    );

    fireEvent.click(screen.getByRole("link", { name: "Analyses" }));
    expect(screen.getByTestId("current-path")).toHaveTextContent("/analyses");
    fireEvent.click(screen.getByRole("button", { name: "Browser back" }));
    expect(await screen.findByTestId("current-path")).toHaveTextContent(
      "/upload",
    );
    fireEvent.click(screen.getByRole("button", { name: "Browser forward" }));
    expect(await screen.findByTestId("current-path")).toHaveTextContent(
      "/analyses",
    );
  });

  it("loads and refreshes a nested analysis URL directly", async () => {
    const first = renderAppAt("/analyses/5/packets");
    expect(await screen.findByText("Analysis #5")).toBeInTheDocument();
    expect(getAnalysis).toHaveBeenCalledWith(5);
    first.unmount();
    vi.mocked(getAnalysis).mockClear();

    renderAppAt("/analyses/5/packets");
    expect(await screen.findByText("Analysis #5")).toBeInTheDocument();
    expect(getAnalysis).toHaveBeenCalledWith(5);
    expect(
      screen.getByRole("navigation", { name: "Analysis 5 navigation" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("navigation", { name: "Breadcrumb" }),
    ).toHaveTextContent("#5 · synthetic.pcap");
  });

  it("shows clear invalid analysis, invalid event, and unknown route states", async () => {
    renderAppAt("/analyses/0/flows");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "positive integer",
    );
    expect(getAnalysis).not.toHaveBeenCalled();
    cleanup();

    vi.mocked(getSecurityEvent).mockRejectedValueOnce(
      new Error("Security event not found."),
    );
    renderAppAt("/events/not-a-valid-event");
    expect(
      await screen.findByText("Security event not found."),
    ).toBeInTheDocument();
    cleanup();

    renderAppAt("/not-a-sentinel-page");
    expect(
      screen.getByRole("heading", { name: "Page not found" }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: "Return to overview" }));
    expect(
      await screen.findByRole("heading", { name: "Security overview" }),
    ).toBeInTheDocument();
  });

  it("renders persisted overview counts, coverage and protocol distribution", async () => {
    vi.mocked(getDashboardOverview).mockResolvedValue(
      dashboardOverview({
        analysis_count: 3,
        completed_analysis_count: 2,
        packet_count: 91,
        flow_count: 18,
        rule_analysis_count: 1,
        rule_finding_count: 2,
        high_priority_finding_count: 1,
        ml_analysis_count: 1,
        ml_anomaly_count: 1,
        hybrid_assessment_count: 1,
        protocol_distribution: [{ protocol: "TCP", flow_count: 12 }],
        recent_analyses: [
          {
            id: 90,
            original_filename: "synthetic-overview.pcap",
            file_size_bytes: 128,
            capture_format: "pcap",
            status: "completed",
            packet_count: 91,
            flow_count: 18,
            flow_generation_status: "completed",
            created_at: "2026-11-16T00:00:00Z",
            detection_status: "completed",
            finding_count: 2,
            ml_status: "completed",
            anomaly_count: 1,
            hybrid_status: "completed",
            risk_score: "62.00",
            severity: "high",
          },
        ],
        recent_high_priority_findings: [
          {
            id: 4,
            analysis_id: 90,
            rule_id: "PORT_SCAN",
            rule_name: "Multi-port probing",
            severity: "high",
            source_ip: "192.0.2.10",
            destination_ip: "198.51.100.20",
            explanation: "Synthetic source contacted multiple target ports.",
            created_at: "2026-11-16T00:00:00Z",
          },
        ],
      }),
    );
    render(<App />);

    expect(
      await screen.findByRole("heading", { name: "Security overview" }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("91", { selector: "p" }),
    ).toBeInTheDocument();
    expect(screen.getByText("synthetic-overview.pcap")).toBeInTheDocument();
    expect(screen.getByText("TCP")).toBeInTheDocument();
    expect(
      screen.getByText("Multi-port probing · analysis #90"),
    ).toBeInTheDocument();
    expect(screen.getByText(/risk 62\.00 \(high\)/)).toBeInTheDocument();
    expect(getDashboardOverview).toHaveBeenCalledOnce();
    fireEvent.click(
      screen.getByRole("link", { name: /synthetic-overview\.pcap/ }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "synthetic.pcap",
      }),
    ).toBeInTheDocument();
  });

  it("shows overview load failures and paginates older analysis history", async () => {
    vi.mocked(getDashboardOverview).mockRejectedValueOnce(
      new Error("Overview service unavailable."),
    );
    vi.mocked(getAnalysisHistory)
      .mockResolvedValueOnce({
        items: [historyAnalysis(analysis(1))],
        total: 101,
        offset: 0,
        limit: 25,
      })
      .mockResolvedValueOnce({
        items: [historyAnalysis(analysis(101))],
        total: 101,
        offset: 25,
        limit: 25,
      });
    renderAppAt("/");

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Overview service unavailable.",
    );
    fireEvent.click(screen.getByRole("link", { name: "Analyses" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Next history" }),
    );
    await waitFor(() =>
      expect(getAnalysisHistory).toHaveBeenLastCalledWith(25, 25),
    );
    expect(
      await screen.findByText("synthetic.pcap", { selector: "span" }),
    ).toBeInTheDocument();
  });

  it("shows the API state and an honest empty state", async () => {
    renderAppAt("/");

    expect(
      await screen.findByText("API and database ready"),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("link", { name: "Analyses" }));
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
    renderAppAt("/upload");
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
    renderAppAt("/upload");
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
    renderAppAt("/upload");
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
    renderAppAt("/analyses/8/packets");
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
    renderAppAt("/analyses/12/flows");
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
    renderAppAt("/analyses/13/flows");
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
    renderAppAt("/analyses/14/flows");
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

    renderAppAt("/analyses/21/rules");
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

    renderAppAt("/analyses/22/rules");
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
    renderAppAt("/analyses/23/rules");
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

    renderAppAt("/analyses/24/rules");
    fireEvent.click(
      await screen.findByRole("button", { name: "Run detection" }),
    );
    expect(
      screen.getByRole("button", { name: "Running detection…" }),
    ).toBeDisabled();

    await act(async () => finishRun?.());
  });

  it("trains a model from selected completed analyses using the API", async () => {
    const eligible = {
      ...analysis(31),
      flow_generation_status: "completed" as const,
      flow_count: 24,
    };
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [eligible],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(trainModel).mockResolvedValue(anomalyModel(4));
    renderAppAt("/analyses/31/ml");

    fireEvent.click(await screen.findByLabelText("synthetic.pcap · 24 flows"));
    fireEvent.click(
      screen.getByRole("button", { name: "Train Isolation Forest" }),
    );

    await waitFor(() =>
      expect(trainModel).toHaveBeenCalledWith({
        analysis_ids: [31],
        n_estimators: 200,
        contamination: "auto",
        max_samples: "auto",
        random_seed: 42,
      }),
    );
    expect(
      await screen.findByRole("option", { name: /Model 4/ }),
    ).toBeInTheDocument();
  });

  it("runs inference and labels returned anomaly scores as indicators", async () => {
    const selected = {
      ...analysis(32),
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
    vi.mocked(getModels).mockResolvedValue({
      items: [anomalyModel(2)],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getMlSummary)
      .mockResolvedValueOnce(mlSummary(32, 2))
      .mockResolvedValueOnce({
        ...mlSummary(32, 2),
        status: "completed",
        result_count: 1,
        anomaly_count: 1,
      });
    vi.mocked(getAnomalyResults).mockResolvedValue(
      anomalyPage([anomalyResult(32, 2)], 1),
    );
    renderAppAt("/analyses/32/ml");
    fireEvent.click(
      await screen.findByRole("button", { name: "Run inference" }),
    );

    expect(await screen.findByText("Anomaly indicator")).toBeInTheDocument();
    expect(screen.getByText("0.125000")).toBeInTheDocument();
    expect(runInference).toHaveBeenCalledWith(32, 2);
  });

  it("filters and paginates real model results", async () => {
    const selected = {
      ...analysis(33),
      flow_generation_status: "completed" as const,
      flow_count: 26,
    };
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [selected],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getAnalysis).mockResolvedValue(selected);
    vi.mocked(getModels).mockResolvedValue({
      items: [anomalyModel(3)],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getMlSummary).mockResolvedValue({
      ...mlSummary(33, 3),
      status: "completed",
      result_count: 26,
      anomaly_count: 13,
      normal_count: 13,
    });
    vi.mocked(getAnomalyResults)
      .mockResolvedValueOnce(
        anomalyPage(
          Array.from({ length: 25 }, (_, index) =>
            anomalyResult(33, 3, index + 1),
          ),
          26,
        ),
      )
      .mockResolvedValueOnce(anomalyPage([anomalyResult(33, 3, 26)], 26))
      .mockResolvedValueOnce(anomalyPage([anomalyResult(33, 3, 26)], 13));
    renderAppAt("/analyses/33/ml");
    expect(await screen.findByText("1–25 of 26")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next anomalies" }));
    await waitFor(() =>
      expect(getAnomalyResults).toHaveBeenLastCalledWith(
        33,
        3,
        25,
        25,
        undefined,
      ),
    );
    fireEvent.change(screen.getByLabelText("Filter anomaly results"), {
      target: { value: "anomaly" },
    });
    await waitFor(() =>
      expect(getAnomalyResults).toHaveBeenLastCalledWith(
        33,
        3,
        0,
        25,
        "anomaly",
      ),
    );
  });

  it("shows inference loading and server error states", async () => {
    const selected = {
      ...analysis(34),
      flow_generation_status: "completed" as const,
      flow_count: 20,
    };
    vi.mocked(getAnalyses).mockResolvedValue({
      items: [selected],
      total: 1,
      offset: 0,
      limit: 100,
    });
    vi.mocked(getAnalysis).mockResolvedValue(selected);
    vi.mocked(getModels).mockResolvedValue({
      items: [anomalyModel(5)],
      total: 1,
      offset: 0,
      limit: 100,
    });
    let rejectInference: ((reason: Error) => void) | undefined;
    vi.mocked(runInference).mockImplementation(
      () =>
        new Promise((_resolve, reject) => {
          rejectInference = reject;
        }),
    );
    renderAppAt("/analyses/34/ml");
    fireEvent.click(
      await screen.findByRole("button", { name: "Run inference" }),
    );
    expect(
      screen.getByRole("button", { name: "Scoring flows…" }),
    ).toBeDisabled();
    await act(async () =>
      rejectInference?.(new Error("Model storage unavailable.")),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Model storage unavailable.",
    );
  });
});

function renderAppAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SentinelApplication />
    </MemoryRouter>,
  );
}

function HistoryControls() {
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <output data-testid="current-path">{location.pathname}</output>
      <button type="button" onClick={() => navigate(-1)}>
        Browser back
      </button>
      <button type="button" onClick={() => navigate(1)}>
        Browser forward
      </button>
    </>
  );
}

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

function historyAnalysis(item: Analysis): OverviewAnalysis {
  return {
    id: item.id,
    original_filename: item.original_filename,
    file_size_bytes: item.file_size_bytes,
    capture_format: item.capture_format,
    status: item.status,
    packet_count: item.packet_count,
    flow_count: null,
    flow_generation_status: item.flow_generation_status,
    created_at: item.created_at,
    detection_status: "not_started",
    finding_count: 0,
    ml_status: "not_started",
    anomaly_count: 0,
    hybrid_status: "not_started",
    risk_score: null,
    severity: null,
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

function anomalyModel(id: number): AnomalyModel {
  return {
    id,
    model_version: `synthetic-model-version-${id}`,
    algorithm: "IsolationForest",
    feature_schema_version: "flow-v1",
    feature_names: ["total_packets"],
    active_feature_names: ["log1p:total_packets"],
    preprocessing_config: {},
    isolation_forest_config: {
      n_estimators: 200,
      contamination: "auto",
      max_samples: "auto",
    },
    random_seed: 42,
    training_analysis_ids: [31],
    training_sample_count: 24,
    training_population_count: 24,
    sklearn_version: "1.9.1",
    status: "ready",
    created_at: "2026-11-16T00:00:00Z",
    trained_at: "2026-11-16T00:00:00Z",
  };
}

function mlSummary(
  analysisId: number,
  modelId: number | null | undefined,
): AnomalySummary {
  return {
    analysis_id: analysisId,
    model_id: modelId ?? null,
    model_version:
      modelId == null ? null : `synthetic-model-version-${modelId}`,
    status: "not_started",
    result_count: 0,
    anomaly_count: 0,
    normal_count: 0,
  };
}

function hybridSummary(analysisId: number): HybridSummary {
  return { analysis_id: analysisId, status: "not_started", assessment: null };
}

function anomalyResult(analysisId: number, modelId: number, id = 9) {
  return {
    id,
    model_id: modelId,
    model_version: `synthetic-model-version-${modelId}`,
    analysis_id: analysisId,
    flow_id: "a".repeat(64),
    prediction: "anomaly" as const,
    anomaly_score: 0.125,
    created_at: "2026-11-16T00:00:00Z",
    flow: {
      flow_id: "a".repeat(64),
      protocol_name: "TCP",
      endpoint_a_ip: "192.0.2.1",
      endpoint_a_port: 51_500,
      endpoint_b_ip: "198.51.100.2",
      endpoint_b_port: 443,
      total_packets: 14,
      total_bytes: 780,
      duration_seconds: "1.25",
    },
  };
}

function anomalyPage(
  items: AnomalyResultList["items"],
  total: number,
  offset = 0,
): AnomalyResultList {
  return {
    items,
    total,
    offset,
    limit: 25,
    model_id: items[0]?.model_id ?? 1,
    model_version: items[0]?.model_version ?? "synthetic-model-version",
  };
}

function dashboardOverview(
  overrides: Partial<DashboardOverview> = {},
): DashboardOverview {
  return {
    analysis_count: 0,
    completed_analysis_count: 0,
    packet_count: 0,
    flow_count: 0,
    rule_finding_count: 0,
    high_priority_finding_count: 0,
    rule_analysis_count: 0,
    ml_anomaly_count: 0,
    ml_analysis_count: 0,
    hybrid_assessment_count: 0,
    severity_counts: {
      informational: 0,
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    },
    protocol_distribution: [],
    recent_analyses: [],
    recent_high_priority_findings: [],
    ...overrides,
  };
}

function syntheticTrafficAnalytics(): TrafficAnalytics {
  return {
    analysis_id: 1,
    original_filename: "SYNTHETIC-app-test.pcap",
    packet_count: 0,
    total_bytes: 0,
    flow_count: null,
    flow_generation_status: "not_started",
    first_packet_timestamp: null,
    last_packet_timestamp: null,
    duration_seconds: null,
    timestamped_packet_count: 0,
    unavailable_timestamp_packet_count: 0,
    packets_per_second: null,
    bytes_per_second: null,
    forward_packets: null,
    backward_packets: null,
    forward_bytes: null,
    backward_bytes: null,
    protocols: [],
    packet_length_distribution: [],
    timeline_bucket_seconds: null,
    timeline: [],
    top_source_endpoints: [],
    top_destination_endpoints: [],
    top_flows_by_bytes: [],
    top_flows_by_packets: [],
  };
}

function syntheticSecurityEvent(): SecurityEvent {
  return {
    event_id: "rule_finding:1",
    event_type: "rule_finding",
    analysis_id: 1,
    original_filename: "SYNTHETIC-app-test.pcap",
    recorded_at: "2026-11-16T00:00:00Z",
    timestamp_label: "finding recorded",
    severity: "high",
    risk_score: null,
    source_ip: "192.0.2.1",
    destination_ip: "198.51.100.2",
    protocol: "TCP",
    explanation: "Synthetic event fixture.",
    rule_id: "PORT_SCAN",
    model_id: null,
    model_version: null,
    flow_id: null,
    related_reference: "rule_finding:1",
  };
}
