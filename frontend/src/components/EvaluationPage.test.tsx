import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { getEvaluation, getEvaluations } from "../api/evaluations";
import EvaluationPage from "./EvaluationPage";

vi.mock("../api/evaluations", () => ({
  getEvaluation: vi.fn(),
  getEvaluations: vi.fn(),
  createEvaluation: vi.fn(),
}));

afterEach(cleanup);

vi.stubGlobal(
  "ResizeObserver",
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
);

describe("EvaluationPage", () => {
  it("shows the persisted-results empty state", async () => {
    vi.mocked(getEvaluations).mockResolvedValue({
      items: [],
      total: 0,
      offset: 0,
      limit: 20,
    });
    render(
      <MemoryRouter>
        <EvaluationPage />
      </MemoryRouter>,
    );
    expect(
      await screen.findByText("No evaluation runs have been recorded."),
    ).toBeInTheDocument();
  });

  it("renders synthetic benchmark metrics from the API response", async () => {
    const run = {
      id: 12,
      dataset_version: "sentinel-synthetic-flow-v1",
      random_seed: 1101,
      repeat_count: 1,
      status: "completed" as const,
      failure_summary: null,
      started_at: "2026-11-17T10:00:00Z",
      completed_at: "2026-11-17T10:00:05Z",
      created_at: "2026-11-17T10:00:00Z",
      results: {
        dataset: {
          synthetic: true,
          test_sample_count: 2,
          training_sample_count: 2,
        },
        model: {
          algorithm: "IsolationForest",
          model_version: "synthetic-model-v1",
        },
        metrics: {
          rule_only: {
            true_positive: 1,
            false_positive: 0,
            true_negative: 1,
            false_negative: 0,
            precision: 1,
            recall: 1,
            f1_score: 1,
            false_positive_rate: 0,
            confusion_matrix: [
              [1, 0],
              [0, 1],
            ],
          },
          ml_only: {
            true_positive: 1,
            false_positive: 1,
            true_negative: 0,
            false_negative: 0,
            precision: 0.5,
            recall: 1,
            f1_score: 0.66,
            false_positive_rate: 1,
            confusion_matrix: [
              [0, 1],
              [0, 1],
            ],
          },
          hybrid: {
            true_positive: 1,
            false_positive: 1,
            true_negative: 0,
            false_negative: 0,
            precision: 0.5,
            recall: 1,
            f1_score: 0.66,
            false_positive_rate: 1,
            confusion_matrix: [
              [0, 1],
              [0, 1],
            ],
          },
          ml_score_thresholds: {
            "0.1": { true_positive: 0 },
            "0.0": { true_positive: 1 },
            "0.05": { true_positive: 1 },
          },
        },
        performance: {
          test_packet_count: 4,
          test_flow_count: 2,
          test_capture_size_bytes: 512,
          stages: { flow_generation: { median_seconds: 0.01 } },
          environment: {
            platform: "Synthetic test platform",
            python_version: "3.12",
            scikit_learn_version: "1.9",
            logical_cpu_count: 4,
          },
        },
        anomaly_score_distribution: {
          unit: "Per-capture maximum score",
          probability: false,
          by_ground_truth: {
            benign: {
              count: 1,
              minimum: -0.123456,
              median: -0.123456,
              p90: -0.123456,
              maximum: -0.123456,
            },
          },
        },
        hybrid_severity_distribution: { high: 1, informational: 1 },
      },
    };
    vi.mocked(getEvaluations).mockResolvedValue({
      items: [run],
      total: 1,
      offset: 0,
      limit: 20,
    });
    vi.mocked(getEvaluation).mockResolvedValue(run);
    render(
      <MemoryRouter>
        <EvaluationPage evaluationId="12" />
      </MemoryRouter>,
    );
    expect(await screen.findByText("Evaluation run #12")).toBeInTheDocument();
    expect(screen.getAllByText("50.0%")).toHaveLength(2);
    expect(screen.getByText(/synthetic captures/i)).toBeInTheDocument();
    expect(
      screen.getByText(/risk scores are not probabilities/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Benchmark environment: Synthetic test platform/),
    ).toBeInTheDocument();
    expect(screen.getAllByText("-0.1235")).toHaveLength(4);
    expect(
      screen
        .getAllByText(/^0\.00$|^0\.05$|^0\.10$/)
        .map((cell) => cell.textContent),
    ).toEqual(["0.00", "0.05", "0.10"]);
  });
});
