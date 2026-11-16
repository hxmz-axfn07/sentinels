import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { Analysis } from "../api/analyses";
import type { DetectionSummary } from "../api/detections";
import { getModels } from "../api/ml";
import { getPipelineSummary, startPipeline } from "../api/pipeline";
import type { PipelineRun } from "../api/pipeline";
import PipelinePanel from "./PipelinePanel";

vi.mock("../api/ml", () => ({
  getModels: vi.fn(),
  getMlSummary: vi.fn(),
}));
vi.mock("../api/pipeline", () => ({
  getPipelineSummary: vi.fn(),
  startPipeline: vi.fn(),
}));

const analysis: Analysis = {
  id: 7,
  original_filename: "synthetic.pcap",
  storage_key: null,
  file_size_bytes: 64,
  capture_format: "pcap",
  status: "completed",
  packet_count: 1,
  error_message: null,
  created_at: "2026-11-16T00:00:00Z",
  completed_at: "2026-11-16T00:00:01Z",
  flow_generation_status: "completed",
  flow_count: 1,
  flow_error_message: null,
  flows_generated_at: "2026-11-16T00:00:01Z",
};

const detectionSummary: DetectionSummary = {
  analysis_id: 7,
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

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getModels).mockResolvedValue({
    items: [],
    total: 0,
    offset: 0,
    limit: 100,
  });
  vi.mocked(getPipelineSummary).mockResolvedValue({
    analysis_id: 7,
    status: "not_started",
    latest_run: null,
  });
});
afterEach(cleanup);

describe("pipeline panel", () => {
  it("submits only the selected stages and displays persisted stage results", async () => {
    vi.mocked(startPipeline).mockResolvedValue(completedRun());
    render(
      <MemoryRouter>
        <PipelinePanel
          analysis={analysis}
          detectionSummary={detectionSummary}
        />
      </MemoryRouter>,
    );

    const runButton = await screen.findByRole("button", {
      name: "Start selected pipeline stages",
    });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(startPipeline).toHaveBeenCalledWith(
        7,
        ["flows", "detection"],
        undefined,
        undefined,
      );
    });
    expect(await screen.findByText("Run #4 stage history")).toBeInTheDocument();
    expect(screen.getByText("finding count: 0")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Rule findings" })).toHaveAttribute(
      "href",
      "/analyses/7/rules",
    );
  });

  it("shows backend prerequisite errors", async () => {
    vi.mocked(startPipeline).mockRejectedValue(
      new Error("Persisted flows are incomplete."),
    );
    render(
      <MemoryRouter>
        <PipelinePanel
          analysis={analysis}
          detectionSummary={detectionSummary}
        />
      </MemoryRouter>,
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Start selected pipeline stages",
      }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Persisted flows are incomplete.",
    );
  });
});

function completedRun(): PipelineRun {
  const now = "2026-11-16T00:00:00Z";
  const stageNames = ["flows", "detection", "inference", "hybrid"] as const;
  return {
    id: 4,
    analysis_id: 7,
    pipeline_version: "pipeline-v1",
    requested_stages: ["flows", "detection"],
    model_id: null,
    model_version: null,
    detection_run_id: 2,
    hybrid_assessment_id: null,
    status: "completed",
    failure_summary: null,
    started_at: now,
    completed_at: now,
    created_at: now,
    risk_score: null,
    severity: null,
    reused_run: false,
    stages: stageNames.map((stage, index) => ({
      id: index + 1,
      run_id: 4,
      analysis_id: 7,
      stage,
      execution_order: index + 1,
      requested: index < 2,
      status: index < 2 ? "completed" : "skipped",
      reused: index === 0,
      result_summary: index === 1 ? { finding_count: 0 } : null,
      error_summary: null,
      started_at: now,
      completed_at: now,
    })),
  };
}
