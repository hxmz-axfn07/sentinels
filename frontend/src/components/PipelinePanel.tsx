import { useEffect, useMemo, useState } from "react";
import type { Analysis } from "../api/analyses";
import type { DetectionSummary } from "../api/detections";
import {
  getMlSummary,
  getModels,
  type AnomalyModel,
  type AnomalySummary,
} from "../api/ml";
import {
  getPipelineSummary,
  startPipeline,
  type PipelineRun,
  type PipelineStageName,
  type PipelineStageStatus,
  type PipelineSummary,
} from "../api/pipeline";

const STAGES: { id: PipelineStageName; label: string }[] = [
  { id: "flows", label: "Generate bidirectional flows" },
  { id: "detection", label: "Run rule detection" },
  { id: "inference", label: "Run ML inference" },
  { id: "hybrid", label: "Create hybrid assessment" },
];

type Props = {
  analysis: Analysis | null;
  detectionSummary: DetectionSummary | null;
  onResultsChanged?: () => void;
};

export default function PipelinePanel({
  analysis,
  detectionSummary,
  onResultsChanged,
}: Props) {
  const [stages, setStages] = useState<PipelineStageName[]>([
    "flows",
    "detection",
  ]);
  const [models, setModels] = useState<AnomalyModel[]>([]);
  const [modelId, setModelId] = useState("");
  const [priorDetectionId, setPriorDetectionId] = useState("");
  const [inferenceSummary, setInferenceSummary] =
    useState<AnomalySummary | null>(null);
  const [summary, setSummary] = useState<PipelineSummary | null>(null);
  const [run, setRun] = useState<PipelineRun | null>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const analysisId = analysis?.id ?? null;
  const includesMl = stages.includes("inference") || stages.includes("hybrid");
  const needsFlows = stages.some((stage) => stage !== "flows");
  const hasFlows = analysis?.flow_generation_status === "completed";
  const requiresExistingDetection =
    stages.includes("hybrid") && !stages.includes("detection");
  const requiresExistingInference =
    stages.includes("hybrid") && !stages.includes("inference");
  const sortedStages = useMemo(
    () => STAGES.map(({ id }) => id).filter((id) => stages.includes(id)),
    [stages],
  );

  useEffect(() => {
    let active = true;
    if (analysisId === null) {
      setModels([]);
      setRun(null);
      setSummary(null);
      setInferenceSummary(null);
      setStages(["flows", "detection"]);
      setModelId("");
      setPriorDetectionId("");
      return () => {
        active = false;
      };
    }
    setLoading(true);
    setError(null);
    setRun(null);
    setSummary(null);
    setStages(["flows", "detection"]);
    setModelId("");
    setPriorDetectionId("");
    setInferenceSummary(null);
    Promise.all([getModels(), getPipelineSummary(analysisId)])
      .then(([modelPage, pipelineSummary]) => {
        if (!active) return;
        setModels(modelPage.items);
        setSummary(pipelineSummary);
        setRun(pipelineSummary.latest_run);
      })
      .catch((reason: unknown) => {
        if (active) setError(errorMessage(reason));
      })
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [analysisId]);

  useEffect(() => {
    let active = true;
    if (analysisId === null || !requiresExistingInference || !modelId) {
      setInferenceSummary(null);
      return () => {
        active = false;
      };
    }
    setInferenceSummary(null);
    getMlSummary(analysisId, Number(modelId))
      .then((value) => active && setInferenceSummary(value))
      .catch(() => active && setInferenceSummary(null));
    return () => {
      active = false;
    };
  }, [analysisId, modelId, requiresExistingInference]);

  useEffect(() => {
    if (!requiresExistingDetection) {
      setPriorDetectionId("");
      return;
    }
    setPriorDetectionId(
      detectionSummary?.status === "completed" &&
        detectionSummary.run_id !== null
        ? String(detectionSummary.run_id)
        : "",
    );
  }, [detectionSummary, requiresExistingDetection]);

  if (!analysis) return null;

  const selectedModel = modelId ? Number(modelId) : undefined;
  const missingFlowPrerequisite =
    needsFlows && !stages.includes("flows") && !hasFlows;
  const missingDetectionPrerequisite =
    requiresExistingDetection && !priorDetectionId;
  const missingInferencePrerequisite =
    requiresExistingInference &&
    (!inferenceSummary ||
      inferenceSummary.status !== "completed" ||
      inferenceSummary.result_count !== analysis.flow_count);
  const invalid =
    analysis.status !== "completed" ||
    stages.length === 0 ||
    (includesMl && !selectedModel) ||
    missingFlowPrerequisite ||
    missingDetectionPrerequisite ||
    missingInferencePrerequisite;

  function toggleStage(stage: PipelineStageName, enabled: boolean) {
    setStages((current) =>
      enabled ? [...current, stage] : current.filter((item) => item !== stage),
    );
  }

  async function handleRun() {
    if (invalid || !analysis) return;
    setRunning(true);
    setError(null);
    try {
      const result = await startPipeline(
        analysis.id,
        sortedStages,
        includesMl ? selectedModel : undefined,
        requiresExistingDetection ? Number(priorDetectionId) : undefined,
      );
      setRun(result);
      setSummary({
        analysis_id: analysis.id,
        status: result.status,
        latest_run: result,
      });
      onResultsChanged?.();
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setRunning(false);
    }
  }

  return (
    <section className="mt-6 rounded-2xl border border-line bg-panel/70 p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-signal">
            Orchestration
          </p>
          <h2 className="mt-1 text-base font-semibold">
            End-to-end analysis pipeline
          </h2>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">
            Select stages explicitly. Existing completed outputs are reused; the
            pipeline never trains a model. Each stage commits independently, so
            a failed later stage does not erase completed earlier results.
          </p>
        </div>
        {run && (
          <span
            className={`rounded-full border px-3 py-1 text-[10px] font-semibold uppercase ${statusClass(run.status)}`}
          >
            Run #{run.id} · {run.status}
          </span>
        )}
      </div>

      <fieldset className="mt-4 grid gap-2 sm:grid-cols-2">
        <legend className="mb-2 text-xs text-slate-400">
          Requested stages
        </legend>
        {STAGES.map((stage) => (
          <label
            key={stage.id}
            className="flex items-center gap-2 text-xs text-slate-300"
          >
            <input
              type="checkbox"
              checked={stages.includes(stage.id)}
              onChange={(event) => toggleStage(stage.id, event.target.checked)}
              disabled={loading || running || analysis.status !== "completed"}
            />
            {stage.label}
          </label>
        ))}
      </fieldset>

      {includesMl && (
        <label className="mt-4 block max-w-xl text-xs text-slate-400">
          Existing Isolation Forest model
          <select
            aria-label="Pipeline model"
            value={modelId}
            onChange={(event) => setModelId(event.target.value)}
            disabled={loading || running || models.length === 0}
            className="mt-1 w-full rounded-lg border border-line bg-ink px-3 py-2 text-sm text-slate-200 disabled:opacity-60"
          >
            <option value="">Select a trained model</option>
            {models.map((model) => (
              <option key={model.id} value={model.id}>
                Model #{model.id} · {model.model_version.slice(0, 8)}
              </option>
            ))}
          </select>
        </label>
      )}

      {requiresExistingDetection && (
        <p className="mt-3 text-xs text-slate-500">
          Hybrid stage uses completed rule run #
          {priorDetectionId || "unavailable"}. Select the rule stage to generate
          or reuse the current configured run.
        </p>
      )}
      {requiresExistingInference && (
        <p className="mt-3 text-xs text-slate-500" role="status">
          {inferenceSummary?.status === "completed" &&
          inferenceSummary.result_count === analysis.flow_count
            ? `Complete inference exists for ${inferenceSummary.model_version?.slice(0, 8)}.`
            : "Hybrid requires complete inference for the selected model. Select the inference stage to run or reuse it."}
        </p>
      )}
      {missingFlowPrerequisite && (
        <p className="mt-3 text-xs text-amber-300" role="status">
          Flow generation has not completed. Select the flow stage before
          detection or inference.
        </p>
      )}
      {analysis.status !== "completed" && (
        <p className="mt-3 text-xs text-amber-300" role="status">
          The capture analysis must complete before the pipeline can run.
        </p>
      )}

      <button
        type="button"
        onClick={() => void handleRun()}
        disabled={loading || running || invalid}
        className="mt-4 rounded-lg border border-signal/40 bg-signal/10 px-4 py-2 text-sm font-semibold text-signal disabled:opacity-40"
      >
        {running ? "Running pipeline…" : "Start selected pipeline stages"}
      </button>
      {loading && (
        <p className="mt-3 text-xs text-slate-400" role="status">
          Loading pipeline state…
        </p>
      )}
      {running && (
        <p className="mt-3 text-xs text-slate-400" role="status">
          Stages run synchronously in dependency order.
        </p>
      )}
      {error && (
        <p className="mt-3 text-sm text-rose-300" role="alert">
          {error}
        </p>
      )}

      {run && !loading && (
        <div className="mt-5 border-t border-line pt-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold">
                Run #{run.id} stage history
              </h3>
              <p className="mt-1 text-xs text-slate-500">
                {run.reused_run
                  ? "Identical completed request reused this run."
                  : "Previously completed stages remain available if a later stage fails."}
              </p>
            </div>
            {run.risk_score !== null && (
              <a
                href="#hybrid-analysis"
                className="text-xs text-signal underline"
              >
                Risk priority {run.risk_score} · {run.severity}
              </a>
            )}
          </div>
          <ol className="mt-3 space-y-2">
            {run.stages.map((stage) => (
              <li
                key={stage.id}
                className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-line bg-ink/50 px-3 py-2"
              >
                <div>
                  <p className="text-xs font-medium text-slate-200">
                    {stage.execution_order}. {stageName(stage.stage)}
                    {!stage.requested && " · prerequisite/reuse state"}
                    {stage.reused && " · reused"}
                  </p>
                  {stage.error_summary && (
                    <p className="mt-1 text-xs text-rose-300">
                      {stage.error_summary}
                    </p>
                  )}
                  {stage.result_summary && (
                    <p className="mt-1 text-xs text-slate-500">
                      {resultText(stage.result_summary)}
                    </p>
                  )}
                </div>
                <span
                  className={`text-[10px] font-semibold uppercase ${statusText(stage.status)}`}
                >
                  {stage.status}
                </span>
              </li>
            ))}
          </ol>
          {run.status === "failed" && (
            <p className="mt-3 text-xs leading-5 text-amber-300">
              {run.failure_summary} Retry by submitting the requested stages
              again; completed outputs are reused and the failed stage is
              retried. Select a different model or configuration for a distinct
              run.
            </p>
          )}
          <nav
            aria-label="Pipeline result sections"
            className="mt-3 flex flex-wrap gap-3 text-xs"
          >
            <a href="#analysis-packets" className="text-signal underline">
              Packets
            </a>
            <a href="#bidirectional-flows" className="text-signal underline">
              Flows
            </a>
            <a href="#rule-findings" className="text-signal underline">
              Rule findings
            </a>
            <a href="#ml-analysis" className="text-signal underline">
              ML results
            </a>
            <a href="#hybrid-analysis" className="text-signal underline">
              Hybrid assessment
            </a>
          </nav>
        </div>
      )}
      {summary?.status === "not_started" && !run && !loading && (
        <p className="mt-3 text-xs text-slate-500">
          No pipeline runs are recorded for this analysis.
        </p>
      )}
    </section>
  );
}

function stageName(stage: PipelineStageName): string {
  return {
    flows: "Bidirectional flow generation",
    detection: "Rule detection",
    inference: "Isolation Forest inference",
    hybrid: "Hybrid assessment",
  }[stage];
}

function resultText(result: Record<string, unknown>): string {
  return Object.entries(result)
    .map(([key, value]) => `${key.replaceAll("_", " ")}: ${String(value)}`)
    .join(" · ");
}

function statusClass(status: string): string {
  if (status === "completed")
    return "border-signal/30 bg-signal/10 text-signal";
  if (status === "failed")
    return "border-rose-400/30 bg-rose-400/10 text-rose-300";
  return "border-amber-400/30 bg-amber-400/10 text-amber-200";
}

function statusText(status: PipelineStageStatus): string {
  if (status === "completed") return "text-signal";
  if (status === "failed") return "text-rose-300";
  if (status === "running") return "text-sky-300";
  return "text-slate-500";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Pipeline request failed.";
}
