import { useEffect, useState, type FormEvent } from "react";
import type { Analysis } from "../api/analyses";
import {
  getAnomalyResults,
  getMlSummary,
  getModels,
  runInference,
  trainModel,
  type AnomalyModel,
  type AnomalyResultList,
  type AnomalySummary,
  type PredictionLabel,
} from "../api/ml";

const PAGE_SIZE = 25;
const MIN_TRAINING_FLOWS = 20;

export default function MlAnalysisPanel({
  analysis,
  analyses,
}: {
  analysis: Analysis | null;
  analyses: Analysis[];
}) {
  const [models, setModels] = useState<AnomalyModel[]>([]);
  const [modelId, setModelId] = useState<number | null>(null);
  const [trainingAnalysisIds, setTrainingAnalysisIds] = useState<number[]>([]);
  const [nEstimators, setNEstimators] = useState(200);
  const [contamination, setContamination] = useState("auto");
  const [maxSamples, setMaxSamples] = useState("auto");
  const [randomSeed, setRandomSeed] = useState(42);
  const [summary, setSummary] = useState<AnomalySummary | null>(null);
  const [results, setResults] = useState<AnomalyResultList | null>(null);
  const [offset, setOffset] = useState(0);
  const [prediction, setPrediction] = useState<"" | PredictionLabel>("");
  const [modelsLoading, setModelsLoading] = useState(true);
  const [training, setTraining] = useState(false);
  const [inference, setInference] = useState(false);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [trainingError, setTrainingError] = useState<string | null>(null);
  const [inferenceError, setInferenceError] = useState<string | null>(null);
  const selectedAnalysisId = analysis?.id;

  useEffect(() => {
    let active = true;
    getModels()
      .then((response) => {
        if (!active) return;
        setModels(response.items);
        setModelId(response.items[0]?.id ?? null);
      })
      .catch((error: unknown) => {
        if (active) setTrainingError(errorMessage(error));
      })
      .finally(() => active && setModelsLoading(false));
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    if (selectedAnalysisId === undefined) {
      setSummary(null);
      setResults(null);
      return () => {
        active = false;
      };
    }
    setResultsLoading(true);
    setResults(null);
    setInferenceError(null);
    getMlSummary(selectedAnalysisId, modelId ?? undefined)
      .then(async (value) => {
        if (!active) return;
        setSummary(value);
        if (value.status === "completed" && value.model_id !== null) {
          const page = await getAnomalyResults(
            selectedAnalysisId,
            value.model_id,
            0,
            PAGE_SIZE,
          );
          if (active) setResults(page);
        } else {
          setResults(null);
        }
        setOffset(0);
      })
      .catch((error: unknown) => {
        if (active) setInferenceError(errorMessage(error));
      })
      .finally(() => active && setResultsLoading(false));
    return () => {
      active = false;
    };
  }, [selectedAnalysisId, modelId]);

  async function handleTrain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setTrainingError(null);
    if (!trainingAnalysisIds.length) {
      setTrainingError(
        "Select at least one completed analysis with generated flows.",
      );
      return;
    }
    const parsedContamination =
      contamination === "auto" ? "auto" : Number(contamination);
    const parsedMaxSamples =
      maxSamples === "auto" ? "auto" : Number(maxSamples);
    if (
      (parsedContamination !== "auto" &&
        (!Number.isFinite(parsedContamination) ||
          parsedContamination <= 0 ||
          parsedContamination > 0.5)) ||
      (parsedMaxSamples !== "auto" &&
        (!Number.isInteger(parsedMaxSamples) || parsedMaxSamples < 2))
    ) {
      setTrainingError("Check contamination and max samples values.");
      return;
    }
    setTraining(true);
    try {
      const model = await trainModel({
        analysis_ids: trainingAnalysisIds,
        n_estimators: nEstimators,
        contamination: parsedContamination,
        max_samples: parsedMaxSamples,
        random_seed: randomSeed,
      });
      setModels((current) => [
        model,
        ...current.filter((item) => item.id !== model.id),
      ]);
      setModelId(model.id);
      setSummary(null);
      setResults(null);
    } catch (error) {
      setTrainingError(errorMessage(error));
    } finally {
      setTraining(false);
    }
  }

  async function handleInference() {
    if (!analysis || modelId === null) return;
    setInference(true);
    setInferenceError(null);
    try {
      await runInference(analysis.id, modelId);
      const [nextSummary, page] = await Promise.all([
        getMlSummary(analysis.id, modelId),
        getAnomalyResults(
          analysis.id,
          modelId,
          0,
          PAGE_SIZE,
          prediction || undefined,
        ),
      ]);
      setSummary(nextSummary);
      setResults(page);
      setOffset(0);
    } catch (error) {
      setInferenceError(errorMessage(error));
    } finally {
      setInference(false);
    }
  }

  async function loadPage(nextOffset: number, nextPrediction = prediction) {
    if (!analysis || modelId === null) return;
    setResultsLoading(true);
    setInferenceError(null);
    try {
      setResults(
        await getAnomalyResults(
          analysis.id,
          modelId,
          nextOffset,
          PAGE_SIZE,
          nextPrediction || undefined,
        ),
      );
      setOffset(nextOffset);
    } catch (error) {
      setInferenceError(errorMessage(error));
    } finally {
      setResultsLoading(false);
    }
  }

  const eligibleAnalyses = analyses.filter(
    (item) =>
      item.status === "completed" &&
      item.flow_generation_status === "completed" &&
      item.flow_count >= MIN_TRAINING_FLOWS,
  );
  const canInfer =
    analysis?.status === "completed" &&
    analysis.flow_generation_status === "completed" &&
    modelId !== null;

  return (
    <section className="mt-6 rounded-2xl border border-line bg-panel/70 p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold">
            Isolation Forest anomalies
          </h2>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">
            Unsupervised anomaly indicators over flow features. An anomaly is
            not a confirmed attack, and the score is not a probability.
          </p>
        </div>
        <p className="text-xs text-slate-400" role="status" aria-live="polite">
          {summary
            ? `${summary.anomaly_count} anomalies · ${summary.normal_count} normal · ${summary.status}`
            : "No inference for this analysis"}
        </p>
      </div>

      <form
        className="mt-5 rounded-xl border border-line p-4"
        onSubmit={handleTrain}
      >
        <h3 className="text-sm font-semibold">Train a model</h3>
        <p className="mt-1 text-xs text-slate-500">
          Select completed analyses with at least {MIN_TRAINING_FLOWS} flows.
          Training is unsupervised; the selected data is not assumed to be
          benign.
        </p>
        {eligibleAnalyses.length ? (
          <fieldset className="mt-3 grid gap-2 sm:grid-cols-2">
            <legend className="sr-only">Training analyses</legend>
            {eligibleAnalyses.map((item) => (
              <label
                key={item.id}
                className="flex items-center gap-2 text-xs text-slate-300"
              >
                <input
                  type="checkbox"
                  checked={trainingAnalysisIds.includes(item.id)}
                  onChange={(event) =>
                    setTrainingAnalysisIds((current) =>
                      event.target.checked
                        ? [...current, item.id]
                        : current.filter((id) => id !== item.id),
                    )
                  }
                />
                {item.original_filename} · {item.flow_count} flows
              </label>
            ))}
          </fieldset>
        ) : (
          <p className="mt-3 text-xs text-slate-500">
            No eligible analyses are available for training.
          </p>
        )}
        <div className="mt-4 grid gap-3 sm:grid-cols-4">
          <label className="text-xs text-slate-400">
            Estimators
            <input
              aria-label="Estimator count"
              className="mt-1 block w-full rounded-md border border-line bg-ink px-2 py-2 text-slate-100"
              type="number"
              min={50}
              max={1000}
              value={nEstimators}
              onChange={(event) => setNEstimators(Number(event.target.value))}
            />
          </label>
          <label className="text-xs text-slate-400">
            Contamination
            <select
              aria-label="Contamination"
              className="mt-1 block w-full rounded-md border border-line bg-ink px-2 py-2 text-slate-100"
              value={contamination}
              onChange={(event) => setContamination(event.target.value)}
            >
              <option value="auto">auto</option>
              <option value="0.01">0.01</option>
              <option value="0.05">0.05</option>
              <option value="0.1">0.1</option>
              <option value="0.25">0.25</option>
              <option value="0.5">0.5</option>
            </select>
          </label>
          <label className="text-xs text-slate-400">
            Max samples
            <select
              aria-label="Maximum samples"
              className="mt-1 block w-full rounded-md border border-line bg-ink px-2 py-2 text-slate-100"
              value={maxSamples}
              onChange={(event) => setMaxSamples(event.target.value)}
            >
              <option value="auto">auto</option>
              <option value="32">32</option>
              <option value="128">128</option>
              <option value="256">256</option>
              <option value="512">512</option>
              <option value="1024">1024</option>
            </select>
          </label>
          <label className="text-xs text-slate-400">
            Random seed
            <input
              aria-label="Random seed"
              className="mt-1 block w-full rounded-md border border-line bg-ink px-2 py-2 text-slate-100"
              type="number"
              min={0}
              value={randomSeed}
              onChange={(event) => setRandomSeed(Number(event.target.value))}
            />
          </label>
        </div>
        {trainingError && (
          <p className="mt-3 text-sm text-rose-300" role="alert">
            {trainingError}
          </p>
        )}
        <button
          type="submit"
          disabled={training || trainingAnalysisIds.length === 0}
          className="mt-4 rounded-lg border border-signal/40 bg-signal/10 px-4 py-2 text-sm font-semibold text-signal disabled:opacity-50"
        >
          {training ? "Training model…" : "Train Isolation Forest"}
        </button>
      </form>

      <div className="mt-5 flex flex-wrap items-end gap-3">
        <label className="min-w-64 text-xs text-slate-400">
          Available model
          <select
            aria-label="Select anomaly model"
            className="mt-1 block w-full rounded-md border border-line bg-ink px-3 py-2 text-slate-100"
            value={modelId ?? ""}
            onChange={(event) =>
              setModelId(event.target.value ? Number(event.target.value) : null)
            }
            disabled={modelsLoading || models.length === 0}
          >
            <option value="">No model selected</option>
            {models.map((model) => (
              <option key={model.id} value={model.id}>
                Model {model.id} · {model.model_version.slice(0, 8)} ·{" "}
                {model.training_sample_count} flows
              </option>
            ))}
          </select>
        </label>
        {modelId !== null && (
          <span className="text-xs text-slate-500">
            {models.find((model) => model.id === modelId)?.algorithm} · flow-v1
            · scikit-learn{" "}
            {models.find((model) => model.id === modelId)?.sklearn_version}
          </span>
        )}
        <button
          type="button"
          disabled={!canInfer || inference}
          onClick={() => void handleInference()}
          className="rounded-lg border border-signal/40 bg-signal/10 px-4 py-2 text-sm font-semibold text-signal disabled:opacity-50"
        >
          {inference ? "Scoring flows…" : "Run inference"}
        </button>
      </div>
      {inferenceError && (
        <p className="mt-3 text-sm text-rose-300" role="alert">
          {inferenceError}
        </p>
      )}

      {summary?.status === "completed" && resultsLoading && !results && (
        <p className="mt-5 py-6 text-center text-sm text-slate-400">
          Loading anomaly results…
        </p>
      )}

      {summary?.status === "completed" && results && (
        <div className="mt-5">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-slate-500">
              {summary.anomaly_count} anomaly indicators ·{" "}
              {summary.normal_count} other flows · score is −decision_function
              (larger means more unusual)
            </p>
            <label className="text-xs text-slate-400">
              Filter prediction
              <select
                aria-label="Filter anomaly results"
                className="ml-2 rounded-md border border-line bg-ink px-2 py-1.5 text-slate-100"
                value={prediction}
                onChange={(event) => {
                  const value = event.target.value as "" | PredictionLabel;
                  setPrediction(value);
                  void loadPage(0, value);
                }}
              >
                <option value="">All predictions</option>
                <option value="anomaly">Anomaly</option>
                <option value="normal">Normal</option>
              </select>
            </label>
          </div>
          {resultsLoading ? (
            <p className="py-6 text-center text-sm text-slate-400">
              Loading anomaly results…
            </p>
          ) : results.items.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-line text-slate-500">
                    <th className="px-3 py-3 font-medium">Prediction</th>
                    <th className="px-3 py-3 font-medium">Endpoint A</th>
                    <th className="px-3 py-3 font-medium">Endpoint B</th>
                    <th className="px-3 py-3 font-medium">Protocol</th>
                    <th className="px-3 py-3 text-right font-medium">
                      Packets / bytes
                    </th>
                    <th className="px-3 py-3 text-right font-medium">
                      Anomaly score
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line/70">
                  {results.items.map((result) => (
                    <tr key={result.id} className="text-slate-300">
                      <td className="px-3 py-3">
                        <span
                          className={
                            result.prediction === "anomaly"
                              ? "text-amber-300"
                              : "text-slate-400"
                          }
                        >
                          {result.prediction === "anomaly"
                            ? "Anomaly indicator"
                            : "Normal"}
                        </span>
                      </td>
                      <td className="px-3 py-3 font-mono">
                        {endpoint(
                          result.flow.endpoint_a_ip,
                          result.flow.endpoint_a_port,
                        )}
                      </td>
                      <td className="px-3 py-3 font-mono">
                        {endpoint(
                          result.flow.endpoint_b_ip,
                          result.flow.endpoint_b_port,
                        )}
                      </td>
                      <td className="px-3 py-3">{result.flow.protocol_name}</td>
                      <td className="px-3 py-3 text-right">
                        {result.flow.total_packets} / {result.flow.total_bytes}{" "}
                        B
                      </td>
                      <td className="px-3 py-3 text-right font-mono">
                        {Number(result.anomaly_score).toFixed(6)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="rounded-xl border border-dashed border-line p-6 text-center text-sm text-slate-500">
              No results match this filter.
            </p>
          )}
          <div className="mt-4 flex items-center justify-between">
            <span className="text-xs text-slate-500">
              {results.total ? offset + 1 : 0}–
              {Math.min(offset + results.items.length, results.total)} of{" "}
              {results.total}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={offset === 0 || resultsLoading}
                onClick={() => void loadPage(Math.max(0, offset - PAGE_SIZE))}
                className="rounded-md border border-line px-3 py-2 text-xs text-slate-300 disabled:opacity-40"
              >
                Previous anomalies
              </button>
              <button
                type="button"
                disabled={offset + PAGE_SIZE >= results.total || resultsLoading}
                onClick={() => void loadPage(offset + PAGE_SIZE)}
                className="rounded-md border border-line px-3 py-2 text-xs text-slate-300 disabled:opacity-40"
              >
                Next anomalies
              </button>
            </div>
          </div>
        </div>
      )}
      {summary?.status === "not_started" && (
        <p className="mt-5 rounded-xl border border-dashed border-line p-6 text-center text-sm text-slate-500">
          Choose a model and run inference on a completed analysis with
          generated flows.
        </p>
      )}
    </section>
  );
}

function endpoint(address: string | null, port: number | null): string {
  if (!address) return "Unknown";
  return port === null ? address : `${address}:${port}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "The machine-learning request failed.";
}
