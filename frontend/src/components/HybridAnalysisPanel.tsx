import { useEffect, useState } from "react";
import type { Analysis } from "../api/analyses";
import type { DetectionSummary } from "../api/detections";
import {
  getHybridEvidence,
  getHybridGroups,
  getHybridSummary,
  runHybridAssessment,
  type HybridAssessment,
  type HybridEvidenceList,
  type HybridRiskGroupList,
  type HybridSeverity,
  type HybridSummary,
} from "../api/hybrid";
import { getModels, type AnomalyModel } from "../api/ml";

const PAGE_SIZE = 10;
const EVIDENCE_PAGE_SIZE = 25;
const SEVERITIES: (HybridSeverity | "")[] = [
  "",
  "informational",
  "low",
  "medium",
  "high",
  "critical",
];

type Props = {
  analysis: Analysis | null;
  detectionSummary: DetectionSummary | null;
  onResultsChanged?: () => void;
};

export default function HybridAnalysisPanel({
  analysis,
  detectionSummary,
  onResultsChanged,
}: Props) {
  const [summary, setSummary] = useState<HybridSummary | null>(null);
  const [models, setModels] = useState<AnomalyModel[]>([]);
  const [selectedModelId, setSelectedModelId] = useState("");
  const [ruleRunId, setRuleRunId] = useState<number | null>(null);
  const [assessment, setAssessment] = useState<HybridAssessment | null>(null);
  const [groups, setGroups] = useState<HybridRiskGroupList | null>(null);
  const [groupOffset, setGroupOffset] = useState(0);
  const [severity, setSeverity] = useState<HybridSeverity | "">("");
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [evidenceGroupId, setEvidenceGroupId] = useState<number | null>(null);
  const [evidence, setEvidence] = useState<HybridEvidenceList | null>(null);
  const [evidenceOffset, setEvidenceOffset] = useState(0);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const analysisId = analysis?.id ?? null;
  const assessmentId = assessment?.id ?? null;

  useEffect(() => {
    let active = true;
    if (analysisId === null) {
      setSummary(null);
      setModels([]);
      setRuleRunId(null);
      setAssessment(null);
      setGroups(null);
      setSelectedModelId("");
      return () => {
        active = false;
      };
    }

    setLoading(true);
    setError(null);
    setSummary(null);
    setAssessment(null);
    setGroups(null);
    setEvidence(null);
    setEvidenceGroupId(null);
    setEvidenceOffset(0);
    Promise.all([getModels(), getHybridSummary(analysisId)])
      .then(([modelPage, hybrid]) => {
        if (!active) return;
        setModels(modelPage.items);
        setSelectedModelId((current) =>
          current &&
          modelPage.items.some((model) => String(model.id) === current)
            ? current
            : "",
        );
        setSummary(hybrid);
        setAssessment(hybrid.assessment);
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
    setRuleRunId(
      analysisId !== null &&
        detectionSummary?.analysis_id === analysisId &&
        detectionSummary.status === "completed"
        ? detectionSummary.run_id
        : null,
    );
  }, [analysisId, detectionSummary]);

  useEffect(() => {
    let active = true;
    if (analysisId === null || assessmentId === null) {
      setGroups(null);
      return () => {
        active = false;
      };
    }
    setLoading(true);
    getHybridGroups(
      analysisId,
      assessmentId,
      groupOffset,
      PAGE_SIZE,
      severity || undefined,
    )
      .then((page) => active && setGroups(page))
      .catch((reason: unknown) => active && setError(errorMessage(reason)))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [analysisId, assessmentId, groupOffset, severity]);

  async function handleRun() {
    if (!analysis || ruleRunId === null || !selectedModelId) return;
    setRunning(true);
    setError(null);
    setEvidence(null);
    setEvidenceGroupId(null);
    try {
      const result = await runHybridAssessment(
        analysis.id,
        ruleRunId,
        Number(selectedModelId),
      );
      setAssessment(result);
      onResultsChanged?.();
      setSummary({
        analysis_id: analysis.id,
        status: "completed",
        assessment: result,
      });
      setGroupOffset(0);
      setSeverity("");
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setRunning(false);
    }
  }

  async function showEvidence(groupId: number) {
    if (!analysis || !assessment) return;
    if (evidenceGroupId === groupId) {
      setEvidenceGroupId(null);
      setEvidence(null);
      setEvidenceOffset(0);
      return;
    }
    setEvidenceGroupId(groupId);
    await loadEvidence(groupId, 0);
  }

  async function loadEvidence(groupId: number, offset: number) {
    if (!analysis || !assessment) return;
    setEvidenceLoading(true);
    setError(null);
    try {
      const page = await getHybridEvidence(
        analysis.id,
        assessment.id,
        groupId,
        offset,
        EVIDENCE_PAGE_SIZE,
      );
      setEvidence(page);
      setEvidenceOffset(offset);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setEvidenceLoading(false);
    }
  }

  if (!analysis) return null;
  const ready =
    analysis.status === "completed" &&
    analysis.flow_generation_status === "completed" &&
    analysis.flow_count > 0;
  const canRun = ready && ruleRunId !== null && selectedModelId !== "";

  return (
    <section
      id="hybrid-analysis"
      className="mt-6 rounded-2xl border border-line bg-panel/70 p-5 sm:p-6"
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-signal">
            Hybrid prioritization
          </p>
          <h2 className="mt-1 text-base font-semibold">
            Correlated risk assessment
          </h2>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">
            Combines selected persisted rule findings and model-relative anomaly
            indicators. Scores prioritize review; they are not probabilities or
            proof of compromise.
          </p>
        </div>
        {assessment && (
          <div className="min-w-28 rounded-xl border border-line bg-ink/60 px-4 py-3 text-right">
            <p className="text-[10px] uppercase tracking-wider text-slate-500">
              Risk score
            </p>
            <p className="font-mono text-2xl font-semibold text-slate-100">
              {Number(assessment.risk_score).toFixed(2)}
            </p>
            <span
              className={`rounded-full border px-2 py-0.5 text-[10px] uppercase ${severityClass(assessment.severity)}`}
            >
              {assessment.severity}
            </span>
          </div>
        )}
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_1.4fr_auto] sm:items-end">
        <label className="block text-xs text-slate-400">
          Completed rule run
          <select
            aria-label="Selected completed rule run"
            value={ruleRunId ?? ""}
            onChange={(event) =>
              setRuleRunId(
                event.target.value ? Number(event.target.value) : null,
              )
            }
            disabled={loading || ruleRunId === null}
            className="mt-1 w-full rounded-lg border border-line bg-ink px-3 py-2 text-sm text-slate-200 disabled:opacity-60"
          >
            {ruleRunId === null ? (
              <option value="">No completed rule run</option>
            ) : (
              <option value={ruleRunId}>Run #{ruleRunId}</option>
            )}
          </select>
        </label>
        <label className="block text-xs text-slate-400">
          Isolation Forest model
          <select
            aria-label="Hybrid model"
            value={selectedModelId}
            onChange={(event) => setSelectedModelId(event.target.value)}
            disabled={loading || models.length === 0}
            className="mt-1 w-full rounded-lg border border-line bg-ink px-3 py-2 text-sm text-slate-200 disabled:opacity-60"
          >
            <option value="">Select a model</option>
            {models.map((model) => (
              <option key={model.id} value={model.id}>
                Model #{model.id} · {model.model_version.slice(0, 8)}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          onClick={() => void handleRun()}
          disabled={!canRun || loading || running}
          className="rounded-lg border border-signal/40 bg-signal/10 px-4 py-2 text-sm font-semibold text-signal disabled:opacity-40"
        >
          {running
            ? "Assessing evidence…"
            : assessment
              ? "Reassess"
              : "Run hybrid assessment"}
        </button>
      </div>

      {!ready && (
        <p className="mt-3 text-xs text-slate-500">
          Complete packet analysis and generate at least one flow first.
        </p>
      )}
      {ready && ruleRunId === null && (
        <p className="mt-3 text-xs text-slate-500">
          Run rule detection for this analysis before hybrid assessment.
        </p>
      )}
      {ready && models.length === 0 && !loading && (
        <p className="mt-3 text-xs text-slate-500">
          Train a model and run inference for this analysis before hybrid
          assessment.
        </p>
      )}
      {loading && !running && (
        <p className="mt-4 text-sm text-slate-400" role="status">
          Loading hybrid assessment…
        </p>
      )}
      {running && (
        <p className="mt-4 text-sm text-slate-400" role="status">
          Correlating the selected persisted rule and ML results…
        </p>
      )}
      {error && (
        <p className="mt-3 text-sm text-rose-300" role="alert">
          {error}
        </p>
      )}

      {assessment && !loading && (
        <>
          <p className="mt-4 text-sm leading-6 text-slate-300">
            {assessment.explanation}
          </p>
          <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-400">
            <Metric
              label="Rule findings"
              value={assessment.rule_evidence_count}
            />
            <Metric label="ML anomalies" value={assessment.ml_anomaly_count} />
            <Metric
              label="Exact correlated flows"
              value={assessment.correlated_evidence_count}
            />
            <Metric label="Risk groups" value={assessment.risk_group_count} />
            <Metric
              label="Rule run"
              value={`#${assessment.detection_run_id}`}
            />
            <Metric
              label="Model"
              value={`#${assessment.model_id} · ${assessment.model_version.slice(0, 8)}`}
            />
            <Metric
              label="Scoring config"
              value={`${assessment.scoring_config_version} · ${assessment.scoring_config_hash.slice(0, 8)}`}
            />
          </div>

          <div className="mt-5 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold">Correlated risk groups</h3>
              <p className="mt-1 text-xs text-slate-500">
                Rule and ML contributions are shown separately for each endpoint
                pair and protocol.
              </p>
            </div>
            <label className="text-xs text-slate-400">
              Filter severity
              <select
                aria-label="Filter hybrid groups by severity"
                value={severity}
                onChange={(event) => {
                  setGroupOffset(0);
                  setSeverity(event.target.value as HybridSeverity | "");
                }}
                className="ml-2 rounded-lg border border-line bg-ink px-2 py-1.5 text-xs text-slate-200"
              >
                {SEVERITIES.map((value) => (
                  <option key={value || "all"} value={value}>
                    {value || "All severities"}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {groups?.items.length ? (
            <div className="mt-3 space-y-3">
              {groups.items.map((group) => (
                <article
                  key={group.id}
                  className="rounded-xl border border-line bg-ink/60 p-4"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase ${severityClass(group.severity)}`}
                    >
                      {group.severity} · {group.risk_score}
                    </span>
                    <span className="font-mono text-xs text-slate-300">
                      {group.endpoint_a_ip ?? "Unknown endpoint"} ↔{" "}
                      {group.endpoint_b_ip ?? "Unknown endpoint"}
                    </span>
                    <span className="rounded border border-line px-2 py-0.5 text-[10px] text-slate-400">
                      {group.protocol_name ?? "Unknown protocol"}
                    </span>
                    <span className="text-[10px] uppercase tracking-wide text-slate-500">
                      {group.correlation_level.replaceAll("_", " ")}
                    </span>
                  </div>
                  <p className="mt-2 text-xs leading-5 text-slate-300">
                    {group.explanation}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-slate-400">
                    <span>Rule contribution: {group.rule_component}</span>
                    <span>ML contribution: {group.ml_component}</span>
                    <span>Exact-flow bonus: {group.exact_flow_bonus}</span>
                    <span>
                      {group.rule_evidence_count} rule ·{" "}
                      {group.ml_anomaly_count} ML
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => void showEvidence(group.id)}
                    className="mt-3 rounded-md border border-line px-3 py-1.5 text-xs text-signal"
                  >
                    {evidenceGroupId === group.id ? "Hide" : "View"} evidence
                  </button>
                  {evidenceGroupId === group.id && (
                    <EvidencePanel
                      page={evidence}
                      loading={evidenceLoading}
                      analysisId={analysis.id}
                      offset={evidenceOffset}
                      onPage={(offset) => void loadEvidence(group.id, offset)}
                    />
                  )}
                </article>
              ))}
              <div className="flex items-center justify-between text-xs text-slate-500">
                <span>
                  {groups.total === 0 ? 0 : groupOffset + 1}–
                  {Math.min(groupOffset + groups.items.length, groups.total)} of{" "}
                  {groups.total}
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    disabled={groupOffset === 0 || loading}
                    onClick={() =>
                      setGroupOffset(Math.max(0, groupOffset - PAGE_SIZE))
                    }
                    className="rounded-md border border-line px-3 py-2 text-slate-300 disabled:opacity-40"
                  >
                    Previous groups
                  </button>
                  <button
                    type="button"
                    disabled={
                      !groups ||
                      groupOffset + PAGE_SIZE >= groups.total ||
                      loading
                    }
                    onClick={() => setGroupOffset(groupOffset + PAGE_SIZE)}
                    className="rounded-md border border-line px-3 py-2 text-slate-300 disabled:opacity-40"
                  >
                    Next groups
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <p className="mt-4 rounded-lg border border-line bg-ink/40 p-4 text-sm text-slate-500">
              {assessment.risk_group_count === 0
                ? "No rule findings or ML anomalies were produced by the selected completed runs. This is not proof that traffic was safe."
                : "No risk groups match this severity filter."}
            </p>
          )}
        </>
      )}
      {summary?.status === "not_started" && !assessment && !loading && (
        <p className="mt-4 text-xs text-slate-500">
          Select the completed rule run and a model after inference to create a
          versioned assessment.
        </p>
      )}
    </section>
  );
}

function EvidencePanel({
  page,
  loading,
  analysisId,
  offset,
  onPage,
}: {
  page: HybridEvidenceList | null;
  loading: boolean;
  analysisId: number;
  offset: number;
  onPage: (offset: number) => void;
}) {
  if (loading)
    return (
      <p className="mt-3 text-xs text-slate-400" role="status">
        Loading evidence…
      </p>
    );
  if (!page) return null;
  return (
    <div className="mt-3 space-y-2 border-l border-line pl-3">
      {page.items.map((item) => (
        <div
          key={item.id}
          className="rounded-lg border border-line/70 bg-black/20 p-3"
        >
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="rounded border border-line px-2 py-0.5 uppercase text-slate-300">
              {item.source}
            </span>
            {item.source === "rule" ? (
              <a className="text-signal underline" href="#rule-findings">
                {item.rule_name} · finding #{item.detection_finding_id}
              </a>
            ) : (
              <a className="text-signal underline" href="#ml-analysis">
                Anomaly result #{item.anomaly_result_id}
              </a>
            )}
            {item.flow_id && (
              <a
                className="font-mono text-slate-400 underline"
                href="#bidirectional-flows"
                title={item.flow_id}
              >
                Flow {item.flow_id.slice(0, 12)}…
              </a>
            )}
            <span className="text-slate-500">Analysis #{analysisId}</span>
          </div>
          <p className="mt-1 text-[11px] text-slate-500">
            {item.rule_id
              ? `${item.rule_id} · ${item.original_severity}`
              : `Model #${item.model_id} · ${item.model_version}`}
            {item.anomaly_score !== null
              ? ` · anomaly score ${item.anomaly_score} (not a probability)`
              : ""}
          </p>
          <details className="mt-2 text-[11px] text-slate-400">
            <summary className="cursor-pointer">
              Original evidence snapshot
            </summary>
            <pre className="mt-2 max-h-64 overflow-auto rounded bg-black/20 p-2 font-mono leading-5">
              {JSON.stringify(item.evidence, null, 2)}
            </pre>
          </details>
        </div>
      ))}
      {page.total > EVIDENCE_PAGE_SIZE && (
        <div className="flex items-center justify-between text-[11px] text-slate-500">
          <span>
            {offset + 1}–{Math.min(offset + page.items.length, page.total)} of{" "}
            {page.total} evidence records
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={offset === 0 || loading}
              onClick={() => onPage(Math.max(0, offset - EVIDENCE_PAGE_SIZE))}
              className="rounded border border-line px-2 py-1 disabled:opacity-40"
            >
              Previous evidence
            </button>
            <button
              type="button"
              disabled={offset + EVIDENCE_PAGE_SIZE >= page.total || loading}
              onClick={() => onPage(offset + EVIDENCE_PAGE_SIZE)}
              className="rounded border border-line px-2 py-1 disabled:opacity-40"
            >
              Next evidence
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <span className="rounded border border-line bg-ink/50 px-2.5 py-1.5">
      {label}: <strong className="font-medium text-slate-300">{value}</strong>
    </span>
  );
}

function severityClass(severity: HybridSeverity): string {
  return {
    informational: "border-slate-500/30 bg-slate-500/10 text-slate-300",
    low: "border-sky-400/30 bg-sky-400/10 text-sky-300",
    medium: "border-amber-300/30 bg-amber-300/10 text-amber-200",
    high: "border-orange-400/30 bg-orange-400/10 text-orange-300",
    critical: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  }[severity];
}

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "The hybrid assessment could not be loaded.";
}
