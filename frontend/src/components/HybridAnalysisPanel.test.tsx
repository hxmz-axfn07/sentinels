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
import type {
  HybridAssessment,
  HybridEvidenceList,
  HybridRiskGroupList,
} from "../api/hybrid";
import type { AnomalyModel } from "../api/ml";
import {
  getHybridEvidence,
  getHybridGroups,
  getHybridSummary,
  runHybridAssessment,
} from "../api/hybrid";
import { getModels } from "../api/ml";
import HybridAnalysisPanel from "./HybridAnalysisPanel";

vi.mock("../api/ml", () => ({ getModels: vi.fn() }));
vi.mock("../api/hybrid", () => ({
  getHybridEvidence: vi.fn(),
  getHybridGroups: vi.fn(),
  getHybridSummary: vi.fn(),
  runHybridAssessment: vi.fn(),
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

beforeEach(() => {
  vi.mocked(getModels).mockResolvedValue({
    items: [model()],
    total: 1,
    offset: 0,
    limit: 100,
  });
  vi.mocked(getHybridSummary).mockResolvedValue({
    analysis_id: 7,
    status: "not_started",
    assessment: null,
  });
  vi.mocked(getHybridGroups).mockResolvedValue(groupPage([], 0));
  vi.mocked(getHybridEvidence).mockResolvedValue(evidencePage());
  vi.mocked(runHybridAssessment).mockResolvedValue(assessment());
});

describe("HybridAnalysisPanel", () => {
  it("runs a version-selected assessment and displays real source evidence", async () => {
    vi.mocked(getHybridGroups).mockResolvedValue(groupPage([group()], 1));
    vi.mocked(getHybridEvidence).mockResolvedValue(evidencePage());
    render(
      <MemoryRouter>
        <HybridAnalysisPanel
          analysis={analysis()}
          detectionSummary={detectionSummary()}
        />
      </MemoryRouter>,
    );

    await screen.findByRole("option", { name: "Run #5" });
    await screen.findByRole("option", { name: /Model #9/ });
    fireEvent.change(screen.getByLabelText("Hybrid model"), {
      target: { value: "9" },
    });
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Run hybrid assessment" }),
      ).toBeEnabled(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Run hybrid assessment" }),
    );

    await waitFor(() =>
      expect(runHybridAssessment).toHaveBeenCalledWith(7, 5, 9),
    );
    expect(await screen.findByText("88.19")).toBeInTheDocument();
    expect(
      await screen.findByText("198.51.100.7 ↔ 203.0.113.9"),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "View evidence" }));
    expect(
      await screen.findByText("Original evidence snapshot"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", {
        name: "Synthetic port probing · finding #31",
      }),
    ).toHaveAttribute("href", "/analyses/7/rules");
    expect(screen.getByText(/synthetic rule evidence/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /finding #31/ })).toHaveAttribute(
      "href",
      "/analyses/7/rules",
    );
  });

  it("shows selection errors and prevents running without prerequisites", async () => {
    const noDetection = {
      ...detectionSummary(),
      status: "not_started",
      run_id: null,
    } as DetectionSummary;
    vi.mocked(getModels).mockResolvedValue({
      items: [],
      total: 0,
      offset: 0,
      limit: 100,
    });
    render(
      <MemoryRouter>
        <HybridAnalysisPanel
          analysis={analysis()}
          detectionSummary={noDetection}
        />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/Run rule detection/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Run hybrid assessment" }),
    ).toBeDisabled();
  });

  it("reports backend prerequisite and assessment errors", async () => {
    vi.mocked(runHybridAssessment).mockRejectedValue(
      new Error("Run inference for every flow first."),
    );
    render(
      <MemoryRouter>
        <HybridAnalysisPanel
          analysis={analysis()}
          detectionSummary={detectionSummary()}
        />
      </MemoryRouter>,
    );
    await screen.findByRole("option", { name: "Run #5" });
    fireEvent.change(screen.getByLabelText("Hybrid model"), {
      target: { value: "9" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Run hybrid assessment" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Run inference for every flow first.",
    );
  });
});

function analysis(): Analysis {
  return {
    id: 7,
    original_filename: "synthetic-day6.pcap",
    storage_key: null,
    file_size_bytes: 64,
    capture_format: "pcap",
    status: "completed",
    packet_count: 3,
    error_message: null,
    created_at: "2026-11-16T00:00:00Z",
    completed_at: "2026-11-16T00:00:01Z",
    flow_generation_status: "completed",
    flow_count: 3,
    flow_error_message: null,
    flows_generated_at: "2026-11-16T00:00:02Z",
  };
}

function detectionSummary(): DetectionSummary {
  return {
    analysis_id: 7,
    run_id: 5,
    status: "completed",
    finding_count: 2,
    severity_counts: { low: 0, medium: 1, high: 1, critical: 0 },
    rule_counts: [{ rule_id: "PORT_SCAN", count: 1 }],
    config_hash: "a".repeat(64),
    error_message: null,
    created_at: "2026-11-16T00:00:00Z",
    completed_at: "2026-11-16T00:00:01Z",
  };
}

function model(): AnomalyModel {
  return {
    id: 9,
    model_version: "synthetic-model-v1",
    algorithm: "IsolationForest",
    feature_schema_version: "flow-v1",
    feature_names: ["total_packets"],
    active_feature_names: ["log1p:total_packets"],
    preprocessing_config: {},
    isolation_forest_config: {},
    random_seed: 42,
    training_analysis_ids: [1],
    training_sample_count: 24,
    training_population_count: 24,
    sklearn_version: "1.9.1",
    status: "ready",
    created_at: "2026-11-16T00:00:00Z",
    trained_at: "2026-11-16T00:00:00Z",
  };
}

function assessment(): HybridAssessment {
  return {
    id: 15,
    analysis_id: 7,
    detection_run_id: 5,
    model_id: 9,
    model_version: "synthetic-model-v1",
    scoring_config_version: "hybrid-v1",
    scoring_config_hash: "b".repeat(64),
    scoring_config: {},
    risk_score: "88.19",
    severity: "critical",
    rule_evidence_count: 2,
    ml_anomaly_count: 2,
    correlated_evidence_count: 1,
    risk_group_count: 2,
    explanation: "Synthetic assessment prioritization.",
    created_at: "2026-11-16T00:00:03Z",
    reused: false,
  };
}

function group(): HybridRiskGroupList["items"][number] {
  return {
    id: 21,
    assessment_id: 15,
    analysis_id: 7,
    group_key: "c".repeat(64),
    correlation_level: "exact_flow",
    endpoint_a_ip: "198.51.100.7",
    endpoint_b_ip: "203.0.113.9",
    protocol_name: "TCP",
    risk_score: "88.19",
    rule_component: "58.75",
    ml_component: "35.00",
    exact_flow_bonus: "15.00",
    severity: "critical",
    rule_evidence_count: 2,
    ml_anomaly_count: 1,
    correlated_flow_count: 1,
    explanation: "Synthetic rule and ML evidence share one exact flow.",
    created_at: "2026-11-16T00:00:03Z",
  };
}

function groupPage(
  items: HybridRiskGroupList["items"],
  total: number,
): HybridRiskGroupList {
  return { items, total, offset: 0, limit: 10, assessment_id: 15 };
}

function evidencePage(): HybridEvidenceList {
  return {
    items: [
      {
        id: 41,
        group_id: 21,
        assessment_id: 15,
        analysis_id: 7,
        source: "rule",
        source_id: 31,
        detection_finding_id: 31,
        anomaly_result_id: null,
        detection_run_id: 5,
        model_id: 9,
        model_version: "synthetic-model-v1",
        flow_id: null,
        rule_id: "PORT_SCAN",
        rule_name: "Synthetic port probing",
        original_severity: "high",
        prediction: null,
        anomaly_score: null,
        evidence: { message: "synthetic rule evidence" },
        created_at: "2026-11-16T00:00:03Z",
      },
    ],
    total: 1,
    offset: 0,
    limit: 25,
    group_id: 21,
  };
}
