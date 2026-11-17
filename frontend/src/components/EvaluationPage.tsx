import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  createEvaluation,
  getEvaluation,
  getEvaluations,
  type EvaluationRun,
  type EvaluationRunSummary,
} from "../api/evaluations";

type MetricSet = Record<string, number | number[][] | null>;
type Results = {
  dataset?: Record<string, unknown>;
  methodology?: Record<string, unknown>;
  configuration?: Record<string, unknown>;
  model?: Record<string, unknown>;
  metrics?: Record<string, MetricSet>;
  rule_category_metrics?: Record<string, Record<string, MetricSet>>;
  hybrid_severity_distribution?: Record<string, number>;
  anomaly_score_distribution?: {
    unit?: string;
    probability?: boolean;
    by_ground_truth?: Record<string, Record<string, number | null>>;
  };
  performance?: {
    test_packet_count?: number;
    test_flow_count?: number;
    test_capture_size_bytes?: number;
    repeat_count?: number;
    stages?: Record<string, Record<string, number | null>>;
    environment?: Record<string, string | number | null>;
    end_to_end_packets_per_second?: number | null;
    end_to_end_flows_per_second?: number | null;
  };
  samples?: Record<string, unknown>[];
};

const card = "rounded-2xl border border-line bg-panel/70 p-5";

export default function EvaluationPage({
  evaluationId,
}: {
  evaluationId?: string;
}) {
  const navigate = useNavigate();
  const [runs, setRuns] = useState<EvaluationRunSummary[]>([]);
  const [run, setRun] = useState<EvaluationRun | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([
      getEvaluations(),
      evaluationId && /^\d+$/.test(evaluationId)
        ? getEvaluation(Number(evaluationId))
        : Promise.resolve(null),
    ])
      .then(([list, detail]) => {
        if (!active) return;
        setRuns(list.items);
        setRun(detail);
        if (evaluationId && !/^\d+$/.test(evaluationId)) {
          setError("Evaluation ID must be a positive integer.");
        }
      })
      .catch((reason: unknown) => {
        if (active)
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to load evaluations.",
          );
      })
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [evaluationId]);

  async function runEvaluation() {
    setRunning(true);
    setError(null);
    try {
      const created = await createEvaluation();
      const summary: EvaluationRunSummary = {
        id: created.id,
        dataset_version: created.dataset_version,
        random_seed: created.random_seed,
        repeat_count: created.repeat_count,
        status: created.status,
        failure_summary: created.failure_summary,
        started_at: created.started_at,
        completed_at: created.completed_at,
        created_at: created.created_at,
      };
      setRuns((current) => [summary, ...current]);
      navigate(`/evaluation/${created.id}`);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Evaluation could not be started.",
      );
    } finally {
      setRunning(false);
    }
  }

  const results = run?.results as Results | null;
  const metrics = results?.metrics;
  const metricRows = ["rule_only", "ml_only", "hybrid"].map((key) => ({
    key,
    label:
      key === "rule_only"
        ? "Rule only"
        : key === "ml_only"
          ? "ML only"
          : "Hybrid",
    precision: metrics?.[key]?.precision ?? null,
    recall: metrics?.[key]?.recall ?? null,
    f1: metrics?.[key]?.f1_score ?? null,
    fpr: metrics?.[key]?.false_positive_rate ?? null,
  }));

  return (
    <section className="py-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-signal">
            Reproducible evaluation
          </p>
          <h1 className="mt-2 text-3xl font-semibold">Detection evaluation</h1>
          <p className="mt-2 max-w-3xl text-sm text-slate-400">
            Runs use labeled synthetic captures and the existing detection
            engines. These results do not establish real-world accuracy.
          </p>
        </div>
        {!evaluationId && (
          <button
            onClick={() => void runEvaluation()}
            disabled={running}
            className="rounded-lg bg-signal px-4 py-2.5 text-sm font-semibold text-ink disabled:opacity-50"
          >
            {running ? "Running benchmark…" : "Run synthetic evaluation"}
          </button>
        )}
      </div>
      {running && (
        <p className="mt-4 text-sm text-slate-400" role="status">
          This bounded synchronous evaluation may take several seconds. Keep
          this page open.
        </p>
      )}
      {error && (
        <p className="mt-4 text-sm text-rose-300" role="alert">
          {error}
        </p>
      )}
      {loading ? (
        <p className="mt-6 text-sm text-slate-400">
          Loading evaluation records…
        </p>
      ) : null}
      {!loading && !runs.length && !error && (
        <div className={`${card} mt-6`}>
          <p className="text-sm text-slate-300">
            No evaluation runs have been recorded.
          </p>
          <p className="mt-2 text-xs text-slate-500">
            Starting an evaluation generates deterministic synthetic PCAP
            samples, trains a fresh model only on the benign training partition,
            and stores aggregate results separately from analyses and incidents.
          </p>
        </div>
      )}
      {runs.length > 0 && (
        <div className={`${card} mt-6`}>
          <h2 className="text-sm font-semibold">Evaluation run history</h2>
          <ul className="mt-3 divide-y divide-line">
            {runs.map((item) => (
              <li key={item.id}>
                <Link
                  className="flex flex-wrap items-center justify-between gap-3 py-3 hover:text-signal"
                  to={`/evaluation/${item.id}`}
                >
                  <span>
                    Run #{item.id} · {item.dataset_version} · seed{" "}
                    {item.random_seed} · {item.repeat_count} repeats
                  </span>
                  <span className="text-xs uppercase text-slate-400">
                    {item.status}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
      {evaluationId && !loading && !run && !error && (
        <p className={`${card} mt-6 text-sm`} role="alert">
          Evaluation run was not found.
        </p>
      )}
      {run && results && (
        <EvaluationReport run={run} results={results} rows={metricRows} />
      )}
      {run?.status === "failed" && (
        <p className={`${card} mt-6 text-sm text-rose-300`}>
          {run.failure_summary ?? "Evaluation failed."}
        </p>
      )}
    </section>
  );
}

function EvaluationReport({
  run,
  results,
  rows,
}: {
  run: EvaluationRun;
  results: Results;
  rows: {
    key: string;
    label: string;
    precision: number | number[][] | null;
    recall: number | number[][] | null;
    f1: number | number[][] | null;
    fpr: number | number[][] | null;
  }[];
}) {
  const dataset = results.dataset;
  const performance = results.performance;
  const metricChart = rows.map((row) => ({
    configuration: row.label,
    precision: percentValue(row.precision),
    recall: percentValue(row.recall),
    F1: percentValue(row.f1),
  }));
  const falsePositiveChart = rows.map((row) => ({
    configuration: row.label,
    "False positive rate": percentValue(row.fpr),
  }));
  const categoryChart = Object.entries(results.rule_category_metrics ?? {}).map(
    ([rule, comparisons]) => {
      const labels: Record<string, string> = {
        PORT_SCAN: "Port scan",
        SYN_FLOOD_LIKE: "SYN-heavy",
        EXCESSIVE_CONNECTION_ATTEMPTS: "Connection attempts",
      };
      return {
        configuration: labels[rule] ?? rule.replaceAll("_", " "),
        Configured: percentValue(comparisons.configured?.recall ?? null),
        "Doubled thresholds": percentValue(
          comparisons.doubled_thresholds?.recall ?? null,
        ),
      };
    },
  );
  const severityOrder: Record<string, number> = {
    informational: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };
  const severityChart = Object.entries(
    results.hybrid_severity_distribution ?? {},
  )
    .sort(
      ([left], [right]) =>
        (severityOrder[left.toLowerCase()] ?? Number.MAX_SAFE_INTEGER) -
        (severityOrder[right.toLowerCase()] ?? Number.MAX_SAFE_INTEGER),
    )
    .map(([severity, count]) => ({ configuration: severity, count }));
  const modelDetails = results.model as Record<string, unknown> | undefined;
  const modelConfiguration = modelDetails?.configuration as
    Record<string, unknown> | undefined;
  const ruleThresholds = results.metrics?.rule_thresholds as unknown as
    Record<string, MetricSet> | undefined;
  const stageLabels: Record<string, string> = {
    packet_parse_and_metadata: "Packet parse",
    flow_generation: "Flows",
    rule_detection: "Rules",
    strict_rule_detection: "Strict rules",
    ml_inference: "Inference",
    hybrid_assessment: "Hybrid",
    training_flow_generation: "Train flows",
    end_to_end_capture_pipeline: "End to end",
  };
  const stageChart = Object.entries(performance?.stages ?? {}).map(
    ([stage, values]) => ({
      stage: stageLabels[stage] ?? stage.replaceAll("_", " "),
      medianMs:
        values.median_seconds == null ? null : values.median_seconds * 1000,
    }),
  );

  return (
    <div className="mt-6 space-y-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">Evaluation run #{run.id}</h2>
          <p className="mt-1 text-xs text-slate-500">
            {run.dataset_version} · completed{" "}
            {run.completed_at
              ? new Date(run.completed_at).toLocaleString()
              : "—"}
          </p>
        </div>
        <Link className="text-sm text-signal hover:underline" to="/evaluation">
          All runs
        </Link>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <SummaryCard
          title="Dataset"
          value={`${dataset?.test_sample_count ?? "—"} test captures`}
          detail={`${dataset?.training_sample_count ?? "—"} training captures · ${String(dataset?.synthetic ? "Synthetic" : "Public")}`}
        />
        <SummaryCard
          title="Test traffic"
          value={`${performance?.test_packet_count ?? "—"} packets · ${performance?.test_flow_count ?? "—"} flows`}
          detail={`${performance?.test_capture_size_bytes ?? "—"} generated capture bytes`}
        />
        <SummaryCard
          title="Model"
          value={String(
            (results.model as Record<string, unknown> | undefined)?.algorithm ??
              "—",
          )}
          detail={`Version ${(results.model as Record<string, unknown> | undefined)?.model_version ?? "—"} · seed ${run.random_seed}`}
        />
        <SummaryCard
          title="End-to-end throughput"
          value={`${performance?.end_to_end_packets_per_second?.toFixed(1) ?? "—"} packets/s`}
          detail={`${performance?.end_to_end_flows_per_second?.toFixed(1) ?? "—"} flows/s · ${performance?.repeat_count ?? run.repeat_count} repeated passes`}
        />
      </div>
      <div className={`${card} grid gap-4 md:grid-cols-2`}>
        <div>
          <h3 className="text-sm font-semibold">Dataset patterns</h3>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            {Object.entries(
              (dataset?.patterns as Record<string, number> | undefined) ?? {},
            )
              .map(
                ([pattern, count]) =>
                  `${pattern.replaceAll("_", " ")} (${count})`,
              )
              .join(" · ") || "Unavailable"}
          </p>
        </div>
        <div>
          <h3 className="text-sm font-semibold">
            Recorded model configuration
          </h3>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            {modelConfiguration
              ? `Isolation Forest · ${modelConfiguration.n_estimators} estimators · contamination ${modelConfiguration.contamination} · max samples ${modelConfiguration.max_samples} · random state ${modelConfiguration.random_state} · schema ${modelDetails?.feature_schema_version} · scikit-learn ${modelDetails?.scikit_learn_version}`
              : "Unavailable"}
          </p>
        </div>
      </div>
      <p className={`${card} text-xs leading-5 text-slate-400`}>
        Benchmark environment:{" "}
        {String(performance?.environment?.platform ?? "unavailable")} · Python{" "}
        {String(performance?.environment?.python_version ?? "unavailable")} ·
        scikit-learn{" "}
        {String(
          performance?.environment?.scikit_learn_version ?? "unavailable",
        )}{" "}
        · {String(performance?.environment?.logical_cpu_count ?? "unknown")}{" "}
        logical CPUs
      </p>
      <div className={card}>
        <h3 className="text-sm font-semibold">
          Capture-level detection metrics
        </h3>
        <p className="mt-1 text-xs text-slate-500">
          Positive means the sample recipe was labeled suspicious before
          detection. Hybrid uses risk score &gt; 0. Anomaly scores and risk
          scores are not probabilities.
        </p>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[650px] text-left text-xs">
            <thead className="text-slate-500">
              <tr>
                {[
                  "Engine",
                  "TP",
                  "FP",
                  "TN",
                  "FN",
                  "Precision",
                  "Recall",
                  "F1",
                  "FPR",
                ].map((name) => (
                  <th key={name} className="px-2 py-2">
                    {name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((row) => {
                const m = results.metrics?.[row.key];
                return (
                  <tr key={row.key}>
                    <td className="px-2 py-3 font-medium">{row.label}</td>
                    <td className="px-2">{m?.true_positive ?? "—"}</td>
                    <td className="px-2">{m?.false_positive ?? "—"}</td>
                    <td className="px-2">{m?.true_negative ?? "—"}</td>
                    <td className="px-2">{m?.false_negative ?? "—"}</td>
                    <td className="px-2">{percent(row.precision)}</td>
                    <td className="px-2">{percent(row.recall)}</td>
                    <td className="px-2">{percent(row.f1)}</td>
                    <td className="px-2">{percent(row.fpr)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
      {ruleThresholds && (
        <div className={`${card} overflow-x-auto`}>
          <h3 className="text-sm font-semibold">Rule threshold comparison</h3>
          <p className="mt-1 text-xs text-slate-500">
            Configured detection thresholds compared with doubled thresholds;
            same samples, no threshold selection against labels.
          </p>
          <table className="mt-3 w-full min-w-[560px] text-left text-xs">
            <thead className="text-slate-500">
              <tr>
                {[
                  "Configuration",
                  "TP",
                  "FP",
                  "TN",
                  "FN",
                  "Precision",
                  "Recall",
                  "F1",
                  "FPR",
                ].map((label) => (
                  <th key={label} className="px-2 py-2">
                    {label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {Object.entries(ruleThresholds).map(([label, metric]) => (
                <tr key={label}>
                  <td className="px-2 py-3">{label.replaceAll("_", " ")}</td>
                  <td className="px-2">{metric.true_positive ?? "—"}</td>
                  <td className="px-2">{metric.false_positive ?? "—"}</td>
                  <td className="px-2">{metric.true_negative ?? "—"}</td>
                  <td className="px-2">{metric.false_negative ?? "—"}</td>
                  <td className="px-2">{percent(metric.precision)}</td>
                  <td className="px-2">{percent(metric.recall)}</td>
                  <td className="px-2">{percent(metric.f1_score)}</td>
                  <td className="px-2">
                    {percent(metric.false_positive_rate)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="grid gap-5 xl:grid-cols-2">
        <ChartCard
          title="Precision, recall and F1"
          data={metricChart}
          dataKey={["precision", "recall", "F1"]}
          unit="%"
        />
        <ChartCard
          title="Median stage duration"
          data={stageChart}
          dataKey={["medianMs"]}
          unit="ms"
        />
      </div>
      <div className="grid gap-5 xl:grid-cols-2">
        <ChartCard
          title="False-positive rate by engine"
          data={falsePositiveChart}
          dataKey={["False positive rate"]}
          unit="%"
        />
        <ChartCard
          title="Hybrid severity distribution"
          data={severityChart}
          dataKey={["count"]}
        />
      </div>
      {categoryChart.length > 0 && (
        <ChartCard
          title="Rule category recall by threshold configuration"
          data={categoryChart}
          dataKey={["Configured", "Doubled thresholds"]}
          unit="%"
        />
      )}
      <div className={`${card} overflow-x-auto`}>
        <h3 className="text-sm font-semibold">
          Isolation Forest score threshold comparison
        </h3>
        <p className="mt-1 text-xs text-slate-500">
          Fixed score thresholds are applied to the same persisted test scores;
          the model was not retrained or tuned on test labels.
        </p>
        <table className="mt-3 w-full min-w-[520px] text-left text-xs">
          <thead className="text-slate-500">
            <tr>
              {[
                "Score >",
                "TP",
                "FP",
                "TN",
                "FN",
                "Precision",
                "Recall",
                "F1",
                "FPR",
              ].map((item) => (
                <th key={item} className="px-2 py-2">
                  {item}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {Object.entries(
              (results.metrics?.ml_score_thresholds ?? {}) as unknown as Record<
                string,
                MetricSet
              >,
            )
              .sort(([left], [right]) => Number(left) - Number(right))
              .map(([threshold, metric]) => (
                <tr key={threshold}>
                  <td className="px-2 py-3">{Number(threshold).toFixed(2)}</td>
                  <td className="px-2">{metric.true_positive ?? "—"}</td>
                  <td className="px-2">{metric.false_positive ?? "—"}</td>
                  <td className="px-2">{metric.true_negative ?? "—"}</td>
                  <td className="px-2">{metric.false_negative ?? "—"}</td>
                  <td className="px-2">{percent(metric.precision)}</td>
                  <td className="px-2">{percent(metric.recall)}</td>
                  <td className="px-2">{percent(metric.f1_score)}</td>
                  <td className="px-2">
                    {percent(metric.false_positive_rate)}
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      <div className={`${card} overflow-x-auto`}>
        <h3 className="text-sm font-semibold">Confusion matrices</h3>
        <p className="mt-1 text-xs text-slate-500">
          Rows are actual benign/suspicious; columns are predicted
          benign/suspicious.
        </p>
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          {rows.map((row) => {
            const matrix = results.metrics?.[row.key]?.confusion_matrix as
              number[][] | undefined;
            return (
              <div key={row.key}>
                <h4 className="mb-2 text-xs font-medium">{row.label}</h4>
                <table className="w-full text-center text-xs">
                  <thead className="text-slate-500">
                    <tr>
                      <th className="p-2">Actual</th>
                      <th className="p-2">Pred. benign</th>
                      <th className="p-2">Pred. suspicious</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(matrix ?? []).map((line, i) => (
                      <tr key={i}>
                        <th className="border border-line p-2 text-left text-slate-500">
                          {i === 0 ? "Benign" : "Suspicious"}
                        </th>
                        {line.map((value, j) => (
                          <td key={j} className="border border-line p-2">
                            {value}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          })}
        </div>
      </div>
      {results.anomaly_score_distribution?.by_ground_truth && (
        <div className={`${card} overflow-x-auto`}>
          <h3 className="text-sm font-semibold">
            Raw anomaly score distribution
          </h3>
          <p className="mt-1 text-xs text-slate-500">
            {results.anomaly_score_distribution.unit ??
              "Per-capture maximum score"}
            ; scores are not probabilities.
          </p>
          <table className="mt-3 w-full text-left text-xs">
            <thead className="text-slate-500">
              <tr>
                {[
                  "Ground truth",
                  "Count",
                  "Minimum",
                  "Median",
                  "P90",
                  "Maximum",
                ].map((name) => (
                  <th key={name} className="px-2 py-2">
                    {name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {Object.entries(
                results.anomaly_score_distribution.by_ground_truth,
              ).map(([label, distribution]) => (
                <tr key={label}>
                  <td className="px-2 py-3">{label}</td>
                  {["count", "minimum", "median", "p90", "maximum"].map(
                    (key) => (
                      <td key={key} className="px-2">
                        {typeof distribution[key] === "number"
                          ? key === "count"
                            ? distribution[key]
                            : distribution[key]!.toFixed(4)
                          : "Undefined"}
                      </td>
                    ),
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className={card}>
        <h3 className="text-sm font-semibold">Method and limitations</h3>
        <ul className="mt-3 list-disc space-y-2 pl-5 text-xs leading-5 text-slate-400">
          <li>
            Dataset labels derive solely from deterministic traffic recipes;
            training and test identifiers are disjoint.
          </li>
          <li>
            Model was trained on the benign training partition only.
            Scikit-learn and feature schema versions are recorded in the report.
          </li>
          <li>
            Synthetic patterns are not representative of real-world traffic.
            Small capture-level results must not be generalized.
          </li>
          <li>
            Rule categories and hybrid severity outputs are preserved in the run
            result. Performance is measured locally on an isolated SQLite
            workspace and is not a production benchmark.
          </li>
        </ul>
        <p className="mt-4 text-xs text-slate-500">
          Hybrid severity distribution:{" "}
          {Object.entries(results.hybrid_severity_distribution ?? {})
            .map(([key, value]) => `${key} ${value}`)
            .join(" · ") || "unavailable"}
        </p>
      </div>
    </div>
  );
}

function SummaryCard({
  title,
  value,
  detail,
}: {
  title: string;
  value: string;
  detail: string;
}) {
  return (
    <div className={card}>
      <p className="text-xs uppercase tracking-wide text-slate-500">{title}</p>
      <p className="mt-2 text-lg font-semibold">{value}</p>
      <p className="mt-1 break-all text-xs text-slate-500">{detail}</p>
    </div>
  );
}

function ChartCard({
  title,
  data,
  dataKey,
  unit = "",
}: {
  title: string;
  data: Record<string, string | number | null>[];
  dataKey: string[];
  unit?: string;
}) {
  return (
    <div className={card}>
      <h3 className="text-sm font-semibold">{title}</h3>
      {data.length ? (
        <div className="mt-4 h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              margin={{ top: 5, right: 10, bottom: 35, left: 0 }}
            >
              <CartesianGrid stroke="#24313b" />
              <XAxis
                dataKey={
                  "configuration" in (data[0] ?? {}) ? "configuration" : "stage"
                }
                angle={-20}
                textAnchor="end"
                interval={0}
                tick={{ fill: "#94a3b8", fontSize: 11 }}
              />
              <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} unit={unit} />
              <Tooltip
                formatter={(value) =>
                  typeof value === "number"
                    ? `${unit === "ms" ? value.toFixed(2) : unit === "%" ? value.toFixed(1) : value}${unit === "ms" ? " ms" : unit === "%" ? "%" : ""}`
                    : "Unavailable"
                }
              />
              <Legend />
              <Bar dataKey={dataKey[0]} fill="#34d399" />
              {dataKey.slice(1).map((key, index) => (
                <Bar
                  key={key}
                  dataKey={key}
                  fill={["#60a5fa", "#fbbf24"][index % 2]}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <p className="mt-5 text-sm text-slate-500">
          No measurements are available.
        </p>
      )}
    </div>
  );
}

function percentValue(value: number | number[][] | null) {
  return typeof value === "number" ? value * 100 : null;
}

function percent(value: number | number[][] | null | undefined) {
  return typeof value === "number"
    ? `${(value * 100).toFixed(1)}%`
    : "Undefined";
}
