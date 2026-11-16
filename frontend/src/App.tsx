import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  BrowserRouter,
  Link,
  NavLink,
  useLocation,
  useNavigate,
} from "react-router-dom";
import {
  getAnalyses,
  getAnalysis,
  getPackets,
  getUploadLimits,
  uploadAnalysis,
  type Analysis,
  type PacketList,
  type UploadLimits,
} from "./api/analyses";
import { getHealth } from "./api/health";
import {
  getDetectionSummary,
  getFindings,
  runDetection,
  type DetectionSeverity,
  type DetectionSummary,
  type FindingList,
} from "./api/detections";
import { generateFlows, getFlows, type FlowList } from "./api/flows";
import MlAnalysisPanel from "./components/MlAnalysisPanel";
import HybridAnalysisPanel from "./components/HybridAnalysisPanel";
import PipelinePanel from "./components/PipelinePanel";
import MonitoringAnalytics from "./components/MonitoringAnalytics";
import { resolveAppRoute } from "./routes";
import {
  getAnalysisHistory,
  getDashboardOverview,
  type DashboardOverview,
  type OverviewAnalysis,
} from "./api/dashboard";

const PACKET_PAGE_SIZE = 50;
const FLOW_PAGE_SIZE = 50;
const FINDING_PAGE_SIZE = 25;
type ServiceStatus = "checking" | "online" | "offline";

export default function App() {
  return (
    <BrowserRouter>
      <SentinelApplication />
    </BrowserRouter>
  );
}

export function SentinelApplication() {
  const location = useLocation();
  const navigate = useNavigate();
  const route = resolveAppRoute(location.pathname);
  const routeAnalysisId = route.params.analysisId;
  const isAnalysisPage = [
    "analysis",
    "packets",
    "flows",
    "rules",
    "ml",
    "hybrid",
    "pipeline",
    "analytics",
  ].includes(route.page);
  const parsedAnalysisId = routeAnalysisId ? Number(routeAnalysisId) : null;
  const validAnalysisId =
    parsedAnalysisId !== null &&
    Number.isSafeInteger(parsedAnalysisId) &&
    parsedAnalysisId > 0;
  const [serviceStatus, setServiceStatus] = useState<ServiceStatus>("checking");
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [history, setHistory] = useState<OverviewAnalysis[]>([]);
  const [analysisTotal, setAnalysisTotal] = useState(0);
  const [historyOffset, setHistoryOffset] = useState(0);
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [limits, setLimits] = useState<UploadLimits | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedAnalysisState, setSelectedAnalysis] =
    useState<Analysis | null>(null);
  const [packets, setPackets] = useState<PacketList | null>(null);
  const [flows, setFlows] = useState<FlowList | null>(null);
  const [detectionSummary, setDetectionSummary] =
    useState<DetectionSummary | null>(null);
  const [findings, setFindings] = useState<FindingList | null>(null);
  const [offset, setOffset] = useState(0);
  const [flowOffset, setFlowOffset] = useState(0);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [packetLoading, setPacketLoading] = useState(false);
  const [flowLoading, setFlowLoading] = useState(false);
  const [flowGenerating, setFlowGenerating] = useState(false);
  const [flowError, setFlowError] = useState<string | null>(null);
  const [findingOffset, setFindingOffset] = useState(0);
  const [findingSeverity, setFindingSeverity] = useState<
    DetectionSeverity | ""
  >("");
  const [findingRule, setFindingRule] = useState("");
  const [findingLoading, setFindingLoading] = useState(false);
  const [detectionRunning, setDetectionRunning] = useState(false);
  const [detectionError, setDetectionError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    getHealth()
      .then(() => active && setServiceStatus("online"))
      .catch(() => active && setServiceStatus("offline"));
    getUploadLimits()
      .then((value) => active && setLimits(value))
      .catch((error: unknown) => {
        if (active) setPageError(errorMessage(error));
      });
    getAnalyses()
      .then((result) => active && setAnalyses(result.items))
      .catch((error: unknown) => {
        if (active) setPageError(errorMessage(error));
      });
    getAnalysisHistory()
      .then((result) => {
        if (active) {
          setHistory(result.items);
          setAnalysisTotal(result.total);
        }
      })
      .catch((error: unknown) => {
        if (active) setPageError(errorMessage(error));
      })
      .finally(() => active && setLoading(false));
    getDashboardOverview()
      .then((result) => active && setOverview(result))
      .catch((error: unknown) => {
        if (active) setOverviewError(errorMessage(error));
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    setPageError(null);
  }, [location.pathname]);

  async function refreshOverview(historyPageOffset = historyOffset) {
    try {
      const [nextOverview, historyPage] = await Promise.all([
        getDashboardOverview(),
        getAnalysisHistory(historyPageOffset),
      ]);
      setOverview(nextOverview);
      setHistory(historyPage.items);
      setAnalysisTotal(historyPage.total);
      setOverviewError(null);
    } catch (error) {
      setOverviewError(errorMessage(error));
    }
  }

  async function loadHistoryPage(nextOffset: number) {
    setLoading(true);
    setPageError(null);
    try {
      const page = await getAnalysisHistory(nextOffset, 25);
      setHistory(page.items);
      setAnalysisTotal(page.total);
      setHistoryOffset(nextOffset);
    } catch (error) {
      setPageError(errorMessage(error));
    } finally {
      setLoading(false);
    }
  }

  const selectAnalysis = useCallback(
    async (id: number, pageOffset = 0) => {
      setPacketLoading(true);
      setPageError(null);
      try {
        const [analysis, packetPage] = await Promise.all([
          getAnalysis(id),
          getPackets(id, pageOffset, PACKET_PAGE_SIZE),
        ]);
        const summary = await getDetectionSummary(id);
        let findingPage: FindingList | null = null;
        if (summary.status === "completed") {
          setFindingLoading(true);
          findingPage = await getFindings(
            id,
            0,
            FINDING_PAGE_SIZE,
            findingSeverity || undefined,
            findingRule || undefined,
          );
        }
        let flowPage: FlowList | null = null;
        if (analysis.flow_generation_status === "completed") {
          setFlowLoading(true);
          flowPage = await getFlows(id, 0, FLOW_PAGE_SIZE);
        }
        setSelectedAnalysis(analysis);
        setPackets(packetPage);
        setOffset(pageOffset);
        setFlows(flowPage);
        setFlowOffset(0);
        setFlowError(null);
        setDetectionSummary(summary);
        setFindings(findingPage);
        setFindingOffset(0);
        setDetectionError(summary.error_message);
      } catch (error) {
        setSelectedAnalysis(null);
        setPageError(errorMessage(error));
      } finally {
        setPacketLoading(false);
        setFlowLoading(false);
        setFindingLoading(false);
      }
    },
    [findingRule, findingSeverity],
  );

  useEffect(() => {
    if (!routeAnalysisId) return;
    if (!validAnalysisId || parsedAnalysisId === null) {
      setSelectedAnalysis(null);
      setPageError(null);
      return;
    }
    if (selectedAnalysisState?.id !== parsedAnalysisId) {
      void selectAnalysis(parsedAnalysisId);
    }
  }, [
    parsedAnalysisId,
    routeAnalysisId,
    selectAnalysis,
    selectedAnalysisState?.id,
    validAnalysisId,
  ]);

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setUploadError(null);
    if (!selectedFile) {
      setUploadError("Choose a PCAP or PCAPNG file first.");
      return;
    }
    if (limits && selectedFile.size > limits.max_upload_size_bytes) {
      return;
    }

    setUploadProgress(0);
    try {
      const result = await uploadAnalysis(selectedFile, setUploadProgress);
      setAnalyses((current) => [
        result,
        ...current.filter((item) => item.id !== result.id),
      ]);
      setHistoryOffset(0);
      const historyPage = await getAnalysisHistory();
      setHistory(historyPage.items);
      setAnalysisTotal(historyPage.total);
      setSelectedAnalysis(result);
      navigate(`/analyses/${result.id}/packets`);
      setOffset(0);
      setFlows(null);
      setFlowOffset(0);
      setDetectionSummary(null);
      setFindings(null);
      setFindingOffset(0);
      const firstPage = await getPackets(result.id, 0, PACKET_PAGE_SIZE);
      setPackets(firstPage);
      setDetectionSummary(await getDetectionSummary(result.id));
      await refreshOverview(0);
      if (result.status === "failed") {
        setUploadError(
          result.error_message ?? "The capture could not be processed.",
        );
      }
    } catch (error) {
      setUploadError(errorMessage(error));
    } finally {
      setUploadProgress(null);
    }
  }

  async function handleGenerateFlows() {
    if (!selectedAnalysis) return;
    setFlowGenerating(true);
    setFlowError(null);
    try {
      const result = await generateFlows(selectedAnalysis.id);
      const updatedAnalysis = {
        ...selectedAnalysis,
        flow_generation_status: result.status,
        flow_count: result.flow_count,
        flow_error_message: null,
        flows_generated_at: result.flows_generated_at,
      };
      setSelectedAnalysis(updatedAnalysis);
      setAnalyses((current) =>
        current.map((item) =>
          item.id === updatedAnalysis.id ? updatedAnalysis : item,
        ),
      );
      setFlowOffset(0);
      setFlowLoading(true);
      setFlows(await getFlows(selectedAnalysis.id, 0, FLOW_PAGE_SIZE));
      await refreshOverview();
    } catch (error) {
      setFlowError(errorMessage(error));
    } finally {
      setFlowGenerating(false);
      setFlowLoading(false);
    }
  }

  async function loadFlowPage(pageOffset: number) {
    if (!selectedAnalysis) return;
    setFlowLoading(true);
    setFlowError(null);
    try {
      setFlows(await getFlows(selectedAnalysis.id, pageOffset, FLOW_PAGE_SIZE));
      setFlowOffset(pageOffset);
    } catch (error) {
      setFlowError(errorMessage(error));
    } finally {
      setFlowLoading(false);
    }
  }

  async function handleRunDetection() {
    if (!selectedAnalysis) return;
    setDetectionRunning(true);
    setDetectionError(null);
    try {
      await runDetection(selectedAnalysis.id);
      const summary = await getDetectionSummary(selectedAnalysis.id);
      const page = await getFindings(
        selectedAnalysis.id,
        0,
        FINDING_PAGE_SIZE,
        findingSeverity || undefined,
        findingRule || undefined,
      );
      setDetectionSummary(summary);
      setFindings(page);
      setFindingOffset(0);
      await refreshOverview();
    } catch (error) {
      setDetectionError(errorMessage(error));
    } finally {
      setDetectionRunning(false);
    }
  }

  async function loadFindingPage(
    pageOffset: number,
    severity = findingSeverity,
    rule = findingRule,
  ) {
    if (!selectedAnalysis || detectionSummary?.status !== "completed") return;
    setFindingLoading(true);
    setDetectionError(null);
    try {
      setFindings(
        await getFindings(
          selectedAnalysis.id,
          pageOffset,
          FINDING_PAGE_SIZE,
          severity || undefined,
          rule || undefined,
        ),
      );
      setFindingOffset(pageOffset);
    } catch (error) {
      setDetectionError(errorMessage(error));
    } finally {
      setFindingLoading(false);
    }
  }

  const statusLabel = {
    checking: "Checking services",
    online: "API and database ready",
    offline: "Services unavailable",
  }[serviceStatus];
  const tooLarge = Boolean(
    selectedFile && limits && selectedFile.size > limits.max_upload_size_bytes,
  );
  const routeAnalysis =
    validAnalysisId && selectedAnalysisState?.id === parsedAnalysisId
      ? selectedAnalysisState
      : null;
  const selectedAnalysis = routeAnalysis;
  const navClass = ({ isActive }: { isActive: boolean }) =>
    `rounded-md px-3 py-2 ${isActive ? "bg-signal/10 text-signal" : "hover:bg-panel hover:text-signal"} focus-visible:outline focus-visible:outline-2 focus-visible:outline-signal`;

  return (
    <main className="min-h-screen bg-ink text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-7xl flex-col px-6 py-6 sm:px-10">
        <header className="flex items-center justify-between border-b border-line pb-5">
          <Link
            className="flex items-center gap-3"
            to="/"
            aria-label="SENTINEL home"
          >
            <span className="grid h-10 w-10 place-items-center rounded-xl border border-signal/30 bg-signal/10 text-sm font-bold text-signal">
              S
            </span>
            <span>
              <span className="block text-sm font-semibold tracking-[0.18em]">
                SENTINEL
              </span>
              <span className="text-xs text-slate-500">NETWORK SECURITY</span>
            </span>
          </Link>
          <div className="flex items-center gap-2 rounded-full border border-line bg-panel px-3 py-2 text-xs text-slate-300">
            <span
              className={`h-2 w-2 rounded-full ${serviceStatus === "online" ? "bg-signal" : serviceStatus === "offline" ? "bg-rose-400" : "bg-amber-300"}`}
              aria-hidden="true"
            />
            <span role="status" aria-live="polite">
              {statusLabel}
            </span>
          </div>
        </header>

        <nav
          aria-label="Main navigation"
          className="sticky top-0 z-10 -mx-6 mt-4 overflow-x-auto border-b border-line bg-ink/95 px-6 py-3 backdrop-blur sm:-mx-10 sm:px-10"
        >
          <ul className="flex min-w-max gap-2 text-xs text-slate-300">
            {(
              [
                ["Overview", "/", true],
                ["Upload", "/upload", true],
                ["Analyses", "/analyses", false],
                ["Security events", "/events", false],
                ["Compare", "/compare", true],
              ] as const
            ).map(([label, target, end]) => (
              <li key={target}>
                <NavLink to={target} end={end} className={navClass}>
                  {label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        <Breadcrumbs route={route} analysis={routeAnalysis} />
        {routeAnalysisId && validAnalysisId && (
          <AnalysisNavigation analysisId={parsedAnalysisId!} />
        )}

        {route.page === "not-found" ? (
          <section className="py-16" role="alert">
            <h1 className="text-2xl font-semibold">Page not found</h1>
            <p className="mt-2 text-sm text-slate-400">
              This SENTINEL page does not exist.
            </p>
            <Link className="mt-4 inline-block text-signal" to="/">
              Return to overview
            </Link>
          </section>
        ) : null}
        {isAnalysisPage && routeAnalysisId && !validAnalysisId ? (
          <p className="mt-5 text-sm text-rose-300" role="alert">
            Analysis ID must be a positive integer.
          </p>
        ) : null}

        {route.page === "overview" && (
          <section id="overview" className="py-8">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.24em] text-signal">
                  Persisted analysis · all-time
                </p>
                <h1 className="mt-2 text-3xl font-semibold tracking-tight">
                  Security overview
                </h1>
                <p className="mt-2 text-sm text-slate-400">
                  Counts reflect completed processing and the latest completed
                  detection, model inference, or hybrid assessment per analysis.
                </p>
              </div>
              <button
                type="button"
                onClick={() => void refreshOverview()}
                className="rounded-lg border border-line px-3 py-2 text-xs text-slate-300 hover:border-signal/50 hover:text-signal"
              >
                Refresh overview
              </button>
            </div>
            {overviewError && (
              <p className="mt-4 text-sm text-rose-300" role="alert">
                {overviewError}
              </p>
            )}
            {!overview && !overviewError ? (
              <p className="mt-6 text-sm text-slate-400" role="status">
                Loading overview…
              </p>
            ) : null}
            {overview && (
              <>
                <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                  <Metric
                    label="Analyses"
                    value={overview.analysis_count}
                    detail={`${overview.completed_analysis_count} completed`}
                  />
                  <Metric
                    label="Packets processed"
                    value={overview.packet_count}
                    detail="Completed capture analyses"
                  />
                  <Metric
                    label="Bidirectional flows"
                    value={overview.flow_count}
                    detail="Generated flows only"
                  />
                  <Metric
                    label="Latest rule findings"
                    value={
                      overview.rule_analysis_count
                        ? overview.rule_finding_count
                        : "—"
                    }
                    detail={`${overview.rule_analysis_count} analyses with completed rule runs`}
                  />
                  <Metric
                    label="ML anomalies"
                    value={
                      overview.ml_analysis_count
                        ? overview.ml_anomaly_count
                        : "—"
                    }
                    detail={`${overview.ml_analysis_count} analyses with inference results`}
                  />
                  <Metric
                    label="Hybrid assessments"
                    value={overview.hybrid_assessment_count || "—"}
                    detail="Latest assessment per analysis"
                  />
                  <Metric
                    label="High or critical findings"
                    value={
                      overview.rule_analysis_count
                        ? overview.high_priority_finding_count
                        : "—"
                    }
                    detail="From latest completed rule runs"
                  />
                </div>
                <div className="mt-5 grid gap-5 lg:grid-cols-2">
                  <div className="rounded-2xl border border-line bg-panel/70 p-5">
                    <h2 className="text-sm font-semibold">
                      Hybrid severity distribution
                    </h2>
                    <p className="mt-1 text-xs text-slate-500">
                      Latest assessment for each analysis
                    </p>
                    <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-5">
                      {Object.entries(overview.severity_counts).map(
                        ([severity, count]) => (
                          <div
                            key={severity}
                            className="rounded-lg bg-ink/70 p-3"
                          >
                            <p className="text-[10px] uppercase tracking-wide text-slate-500">
                              {severity}
                            </p>
                            <p className="mt-1 text-xl font-semibold">
                              {count}
                            </p>
                          </div>
                        ),
                      )}
                    </div>
                    <p className="mt-3 text-xs text-slate-500">
                      Missing assessments are not represented as normal or safe.
                    </p>
                  </div>
                  <div className="rounded-2xl border border-line bg-panel/70 p-5">
                    <h2 className="text-sm font-semibold">Flow protocols</h2>
                    <p className="mt-1 text-xs text-slate-500">
                      Persisted flows across completed flow-generation stages
                    </p>
                    {overview.protocol_distribution.length ? (
                      <ul className="mt-4 space-y-3">
                        {overview.protocol_distribution.map((item) => {
                          const max = Math.max(
                            ...overview.protocol_distribution.map(
                              (row) => row.flow_count,
                            ),
                            1,
                          );
                          return (
                            <li key={item.protocol}>
                              <div className="mb-1 flex justify-between text-xs">
                                <span>{item.protocol}</span>
                                <span className="text-slate-400">
                                  {item.flow_count}
                                </span>
                              </div>
                              <div className="h-2 rounded-full bg-ink">
                                <div
                                  className="h-2 rounded-full bg-signal/80"
                                  style={{
                                    width: `${(item.flow_count / max) * 100}%`,
                                  }}
                                />
                              </div>
                            </li>
                          );
                        })}
                      </ul>
                    ) : (
                      <p className="mt-5 text-sm text-slate-500">
                        No generated flow records are available.
                      </p>
                    )}
                  </div>
                </div>
                <div className="mt-5 rounded-2xl border border-line bg-panel/70 p-5">
                  <h2 className="text-sm font-semibold">
                    Recent high-priority rule findings
                  </h2>
                  <p className="mt-1 text-xs text-slate-500">
                    High and critical findings from each analysis's latest
                    completed rule run.
                  </p>
                  {overview.recent_high_priority_findings.length ? (
                    <ul className="mt-3 divide-y divide-line">
                      {overview.recent_high_priority_findings.map((finding) => (
                        <li key={finding.id}>
                          <button
                            type="button"
                            onClick={() =>
                              void selectAnalysis(finding.analysis_id)
                            }
                            className="flex w-full flex-wrap items-center justify-between gap-3 py-3 text-left hover:text-signal"
                          >
                            <span>
                              <span className="block text-sm font-medium">
                                {finding.rule_name} · analysis #
                                {finding.analysis_id}
                              </span>
                              <span className="mt-1 block text-xs text-slate-400">
                                {finding.explanation}
                              </span>
                              <span className="mt-1 block font-mono text-[11px] text-slate-500">
                                {finding.source_ip ?? "—"} →{" "}
                                {finding.destination_ip ?? "—"}
                              </span>
                            </span>
                            <span
                              className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase ${finding.severity === "critical" ? "border-rose-400/30 bg-rose-400/10 text-rose-200" : "border-orange-400/30 bg-orange-400/10 text-orange-200"}`}
                            >
                              {finding.severity}
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="mt-4 text-sm text-slate-500">
                      No high or critical findings in the available completed
                      rule runs.
                    </p>
                  )}
                </div>
                <div className="mt-5 rounded-2xl border border-line bg-panel/70 p-5">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-sm font-semibold">Recent analyses</h2>
                      <p className="mt-1 text-xs text-slate-500">
                        Open an analysis to inspect its stored results.
                      </p>
                    </div>
                    <Link
                      to="/analyses"
                      className="text-xs text-signal hover:underline"
                    >
                      Full history
                    </Link>
                  </div>
                  {overview.recent_analyses.length ? (
                    <div className="mt-3 divide-y divide-line">
                      {overview.recent_analyses.map((item) => (
                        <Link
                          key={item.id}
                          to={`/analyses/${item.id}`}
                          className="flex w-full flex-wrap items-center justify-between gap-3 py-3 text-left hover:text-signal"
                        >
                          <span>
                            <span className="block text-sm font-medium">
                              {item.original_filename}
                            </span>
                            <span className="mt-1 block text-xs text-slate-500">
                              {item.capture_format.toUpperCase()} ·{" "}
                              {item.packet_count === null
                                ? "—"
                                : item.packet_count}{" "}
                              packets ·{" "}
                              {item.flow_count === null ? "—" : item.flow_count}{" "}
                              flows
                            </span>
                          </span>
                          <span className="text-xs text-slate-400">
                            Rules {item.detection_status} · ML {item.ml_status}{" "}
                            · Hybrid {item.hybrid_status}
                            {item.risk_score === null
                              ? ""
                              : ` · risk ${item.risk_score} (${item.severity})`}
                          </span>
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <p className="mt-4 text-sm text-slate-500">
                      No recent analyses are available.
                    </p>
                  )}
                </div>
              </>
            )}
          </section>
        )}

        {route.page === "upload" && (
          <>
            <section id="upload" className="py-10">
              <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-signal">
                Offline capture analysis
              </p>
              <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">
                PCAP ingestion
              </h1>
              <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
                Upload an authorized PCAP or PCAPNG capture. SENTINEL records
                packet metadata without storing packet payloads.
              </p>
            </section>

            <div className="grid gap-6 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.5fr)]">
              <section className="rounded-2xl border border-line bg-panel/70 p-5 sm:p-6">
                <h2 className="text-base font-semibold">Upload a capture</h2>
                <p className="mt-2 text-sm text-slate-400">
                  PCAP and PCAPNG are identified from file contents.
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  Maximum size:{" "}
                  {limits
                    ? formatBytes(limits.max_upload_size_bytes)
                    : "Loading limit…"}
                </p>
                <form className="mt-5 space-y-4" onSubmit={handleUpload}>
                  <label
                    className="block text-sm font-medium text-slate-300"
                    htmlFor="capture-file"
                  >
                    Capture file
                  </label>
                  <input
                    id="capture-file"
                    type="file"
                    accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/x-pcapng"
                    onChange={(event) => {
                      setSelectedFile(event.currentTarget.files?.[0] ?? null);
                      setUploadError(null);
                    }}
                    className="block w-full cursor-pointer rounded-lg border border-line bg-ink p-3 text-sm text-slate-300 file:mr-4 file:rounded-md file:border-0 file:bg-signal/10 file:px-3 file:py-2 file:text-xs file:font-semibold file:text-signal"
                  />
                  {selectedFile && (
                    <p className="text-xs text-slate-500">
                      {selectedFile.name} · {formatBytes(selectedFile.size)}
                    </p>
                  )}
                  {tooLarge && (
                    <p className="text-sm text-rose-300" role="alert">
                      This file exceeds the configured upload limit.
                    </p>
                  )}
                  {uploadError && (
                    <p className="text-sm text-rose-300" role="alert">
                      {uploadError}
                    </p>
                  )}
                  {uploadProgress !== null && (
                    <div>
                      <div className="mb-1 flex justify-between text-xs text-slate-400">
                        <span>Uploading and analyzing</span>
                        <span>{uploadProgress}%</span>
                      </div>
                      <progress
                        className="h-2 w-full accent-signal"
                        aria-label="Upload progress"
                        max={100}
                        value={uploadProgress}
                      />
                    </div>
                  )}
                  <button
                    type="submit"
                    disabled={
                      !selectedFile ||
                      !limits ||
                      tooLarge ||
                      uploadProgress !== null
                    }
                    className="rounded-lg bg-signal px-4 py-2.5 text-sm font-semibold text-ink transition-colors hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {uploadProgress === null
                      ? "Upload and analyze"
                      : "Processing…"}
                  </button>
                </form>
              </section>
            </div>
          </>
        )}

        {route.page === "analyses" && (
          <section
            id="analysis-history"
            className="scroll-mt-20 rounded-2xl border border-line bg-panel/70 p-5 sm:p-6"
          >
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold">Analyses</h2>
              <span className="text-xs text-slate-500">
                {analysisTotal === 0
                  ? "0 analyses"
                  : `${analysisTotal} total · ${historyOffset + 1}–${Math.min(historyOffset + history.length, analysisTotal)} shown`}
              </span>
            </div>
            {loading ? (
              <p className="mt-5 text-sm text-slate-400">Loading analyses…</p>
            ) : history.length === 0 ? (
              <p className="mt-5 rounded-xl border border-dashed border-line p-6 text-center text-sm text-slate-500">
                No captures have been analyzed yet.
              </p>
            ) : (
              <ul className="mt-4 divide-y divide-line">
                {history.map((analysis) => (
                  <li key={analysis.id}>
                    <Link
                      className="flex w-full items-center justify-between gap-4 py-3 text-left hover:text-signal"
                      to={`/analyses/${analysis.id}`}
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">
                          {analysis.original_filename}
                        </span>
                        <span className="mt-1 block text-xs text-slate-500">
                          {analysis.capture_format.toUpperCase()} ·{" "}
                          {formatBytes(analysis.file_size_bytes)} ·{" "}
                          {analysis.packet_count ?? "—"} packets ·{" "}
                          {analysis.flow_count ?? "—"} flows ·{" "}
                          {new Date(analysis.created_at).toLocaleString()}
                          <span className="mt-1 block text-[11px] text-slate-500">
                            Rules {analysis.detection_status}
                            {analysis.detection_status === "completed"
                              ? ` (${analysis.finding_count})`
                              : ""}{" "}
                            · ML {analysis.ml_status}
                            {analysis.ml_status === "completed"
                              ? ` (${analysis.anomaly_count} anomalies)`
                              : ""}{" "}
                            · Hybrid {analysis.hybrid_status}
                            {analysis.risk_score === null
                              ? ""
                              : ` (${analysis.risk_score} · ${analysis.severity})`}
                          </span>
                        </span>
                      </span>
                      <StatusBadge status={analysis.status} />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
            {analysisTotal > 25 && (
              <div className="mt-4 flex justify-end gap-2">
                <button
                  type="button"
                  disabled={historyOffset === 0 || loading}
                  onClick={() =>
                    void loadHistoryPage(Math.max(0, historyOffset - 25))
                  }
                  className="rounded-md border border-line px-3 py-2 text-xs disabled:opacity-40"
                >
                  Previous history
                </button>
                <button
                  type="button"
                  disabled={historyOffset + 25 >= analysisTotal || loading}
                  onClick={() => void loadHistoryPage(historyOffset + 25)}
                  className="rounded-md border border-line px-3 py-2 text-xs disabled:opacity-40"
                >
                  Next history
                </button>
              </div>
            )}
          </section>
        )}

        {pageError && (
          <p className="mt-5 text-sm text-rose-300" role="alert">
            {pageError}
          </p>
        )}

        {route.page === "analysis" && (
          <AnalysisDetails analysis={routeAnalysis} loading={packetLoading} />
        )}

        {route.page === "packets" && validAnalysisId && !selectedAnalysis && (
          <SectionPlaceholder
            id="analysis-packets"
            title="Packet metadata"
            message="Upload a capture or open an analysis from history to inspect its packets."
          />
        )}
        {route.page === "packets" && selectedAnalysis && (
          <section
            id="analysis-packets"
            className="mt-6 rounded-2xl border border-line bg-panel/70 p-5 sm:p-6"
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-widest text-slate-500">
                  Analysis #{selectedAnalysis.id}
                </p>
                <h2 className="mt-2 text-lg font-semibold">
                  {selectedAnalysis.original_filename}
                </h2>
                <p className="mt-1 text-sm text-slate-400">
                  {selectedAnalysis.capture_format.toUpperCase()} ·{" "}
                  {formatBytes(selectedAnalysis.file_size_bytes)} ·{" "}
                  {selectedAnalysis.packet_count} packets
                </p>
              </div>
              <StatusBadge status={selectedAnalysis.status} />
            </div>
            {selectedAnalysis.error_message && (
              <p className="mt-4 text-sm text-rose-300" role="alert">
                {selectedAnalysis.error_message}
              </p>
            )}
            <div className="mt-6 flex items-center justify-between">
              <h3 className="text-sm font-semibold">Packet metadata</h3>
              {packets && (
                <span className="text-xs text-slate-500">
                  {packets.total === 0 ? 0 : offset + 1}–
                  {Math.min(offset + packets.items.length, packets.total)} of{" "}
                  {packets.total}
                </span>
              )}
            </div>
            {packetLoading ? (
              <p className="py-8 text-center text-sm text-slate-400">
                Loading packet metadata…
              </p>
            ) : packets?.items.length ? (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full min-w-[760px] border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line text-slate-500">
                      <th className="px-3 py-3 font-medium">#</th>
                      <th className="px-3 py-3 font-medium">Timestamp</th>
                      <th className="px-3 py-3 font-medium">Source</th>
                      <th className="px-3 py-3 font-medium">Destination</th>
                      <th className="px-3 py-3 font-medium">Protocol</th>
                      <th className="px-3 py-3 text-right font-medium">
                        Bytes
                      </th>
                      <th className="px-3 py-3 font-medium">TCP flags</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line/70">
                    {packets.items.map((packet) => (
                      <tr key={packet.id} className="text-slate-300">
                        <td className="px-3 py-3 text-slate-500">
                          {packet.packet_index}
                        </td>
                        <td className="px-3 py-3 font-mono">
                          {packet.timestamp ?? "—"}
                        </td>
                        <td className="px-3 py-3 font-mono">
                          {endpoint(packet.source_ip, packet.source_port)}
                        </td>
                        <td className="px-3 py-3 font-mono">
                          {endpoint(
                            packet.destination_ip,
                            packet.destination_port,
                          )}
                        </td>
                        <td className="px-3 py-3">
                          {packet.transport_protocol ?? packet.network_protocol}
                        </td>
                        <td className="px-3 py-3 text-right">
                          {packet.packet_length}
                        </td>
                        <td className="px-3 py-3 font-mono">
                          {packet.tcp_flags === null
                            ? "—"
                            : `0x${packet.tcp_flags.toString(16).toUpperCase()}`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="py-8 text-center text-sm text-slate-500">
                {selectedAnalysis.status === "failed"
                  ? "No packet metadata was stored."
                  : "This analysis has no packets."}
              </p>
            )}
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                disabled={offset === 0 || packetLoading}
                onClick={() =>
                  void selectAnalysis(
                    selectedAnalysis.id,
                    Math.max(0, offset - PACKET_PAGE_SIZE),
                  )
                }
                className="rounded-md border border-line px-3 py-2 text-xs text-slate-300 disabled:opacity-40"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={
                  !packets ||
                  offset + PACKET_PAGE_SIZE >= packets.total ||
                  packetLoading
                }
                onClick={() =>
                  void selectAnalysis(
                    selectedAnalysis.id,
                    offset + PACKET_PAGE_SIZE,
                  )
                }
                className="rounded-md border border-line px-3 py-2 text-xs text-slate-300 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </section>
        )}

        {route.page === "flows" && validAnalysisId && !selectedAnalysis && (
          <SectionPlaceholder
            id="bidirectional-flows"
            title="Bidirectional flows"
            message="Select an analysis to generate and inspect persisted network flows."
          />
        )}
        {route.page === "flows" && selectedAnalysis && (
          <section
            id="bidirectional-flows"
            className="mt-6 rounded-2xl border border-line bg-panel/70 p-5 sm:p-6"
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-semibold">Bidirectional flows</h2>
                <p className="mt-1 text-xs text-slate-500">
                  {selectedAnalysis.flow_count} flows ·{" "}
                  {selectedAnalysis.flow_generation_status.replaceAll("_", " ")}
                </p>
              </div>
              {selectedAnalysis.status === "completed" &&
                selectedAnalysis.flow_generation_status !== "completed" && (
                  <button
                    type="button"
                    onClick={() => void handleGenerateFlows()}
                    disabled={
                      flowGenerating ||
                      selectedAnalysis.flow_generation_status === "processing"
                    }
                    className="rounded-lg border border-signal/40 bg-signal/10 px-4 py-2 text-sm font-semibold text-signal disabled:opacity-50"
                  >
                    {flowGenerating
                      ? "Generating flows…"
                      : selectedAnalysis.flow_generation_status === "failed"
                        ? "Retry flow generation"
                        : "Generate flows"}
                  </button>
                )}
            </div>
            {selectedAnalysis.flow_error_message && (
              <p className="mt-3 text-sm text-rose-300" role="alert">
                {selectedAnalysis.flow_error_message}
              </p>
            )}
            {flowError && (
              <p className="mt-3 text-sm text-rose-300" role="alert">
                {flowError}
              </p>
            )}
            {flowLoading ? (
              <p className="py-8 text-center text-sm text-slate-400">
                Loading flows…
              </p>
            ) : selectedAnalysis.flow_generation_status !== "completed" ? (
              <p className="py-8 text-center text-sm text-slate-500">
                Generate flows after packet analysis has completed.
              </p>
            ) : flows?.items.length ? (
              <>
                <div className="mt-4 overflow-x-auto">
                  <table className="w-full min-w-[900px] border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-line text-slate-500">
                        <th className="px-3 py-3 font-medium">Endpoint A</th>
                        <th className="px-3 py-3 font-medium">Endpoint B</th>
                        <th className="px-3 py-3 font-medium">Protocol</th>
                        <th className="px-3 py-3 text-right font-medium">
                          Packets A→B
                        </th>
                        <th className="px-3 py-3 text-right font-medium">
                          Packets B→A
                        </th>
                        <th className="px-3 py-3 text-right font-medium">
                          Bytes
                        </th>
                        <th className="px-3 py-3 text-right font-medium">
                          Duration (s)
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line/70">
                      {flows.items.map((flow) => (
                        <tr key={flow.flow_id} className="text-slate-300">
                          <td className="px-3 py-3 font-mono">
                            {endpoint(flow.endpoint_a_ip, flow.endpoint_a_port)}
                          </td>
                          <td className="px-3 py-3 font-mono">
                            {endpoint(flow.endpoint_b_ip, flow.endpoint_b_port)}
                          </td>
                          <td className="px-3 py-3">
                            {flow.protocol_name}
                            {flow.protocol_number === null
                              ? ""
                              : ` (${flow.protocol_number})`}
                          </td>
                          <td className="px-3 py-3 text-right">
                            {flow.forward_packets} · {flow.forward_bytes} B
                          </td>
                          <td className="px-3 py-3 text-right">
                            {flow.backward_packets} · {flow.backward_bytes} B
                          </td>
                          <td className="px-3 py-3 text-right">
                            {flow.total_bytes}
                          </td>
                          <td className="px-3 py-3 text-right font-mono">
                            {formatNumber(flow.duration_seconds)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="mt-4 flex items-center justify-between">
                  <span className="text-xs text-slate-500">
                    {flows.total === 0 ? 0 : flowOffset + 1}–
                    {Math.min(flowOffset + flows.items.length, flows.total)} of{" "}
                    {flows.total}
                  </span>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={flowOffset === 0 || flowLoading}
                      onClick={() =>
                        void loadFlowPage(
                          Math.max(0, flowOffset - FLOW_PAGE_SIZE),
                        )
                      }
                      className="rounded-md border border-line px-3 py-2 text-xs text-slate-300 disabled:opacity-40"
                    >
                      Previous flows
                    </button>
                    <button
                      type="button"
                      disabled={
                        !flows ||
                        flowOffset + FLOW_PAGE_SIZE >= flows.total ||
                        flowLoading
                      }
                      onClick={() =>
                        void loadFlowPage(flowOffset + FLOW_PAGE_SIZE)
                      }
                      className="rounded-md border border-line px-3 py-2 text-xs text-slate-300 disabled:opacity-40"
                    >
                      Next flows
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <p className="py-8 text-center text-sm text-slate-500">
                Flow generation completed with no packet conversations.
              </p>
            )}
          </section>
        )}

        {route.page === "rules" && validAnalysisId && !selectedAnalysis && (
          <SectionPlaceholder
            id="rule-findings"
            title="Rule detection"
            message="Select an analysis with generated flows to run and inspect configured detection rules."
          />
        )}
        {route.page === "rules" && selectedAnalysis && (
          <section
            id="rule-findings"
            className="mt-6 rounded-2xl border border-line bg-panel/70 p-5 sm:p-6"
          >
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-semibold">Rule-based findings</h2>
                <p className="mt-1 text-xs text-slate-500">
                  {detectionSummary?.finding_count ?? 0} findings ·{" "}
                  {detectionSummary?.status ?? "not_started"}
                </p>
              </div>
              {selectedAnalysis.status === "completed" &&
                selectedAnalysis.flow_generation_status === "completed" && (
                  <button
                    type="button"
                    onClick={() => void handleRunDetection()}
                    disabled={
                      detectionRunning ||
                      detectionSummary?.status === "processing"
                    }
                    className="rounded-lg border border-signal/40 bg-signal/10 px-4 py-2 text-sm font-semibold text-signal disabled:opacity-50"
                  >
                    {detectionRunning
                      ? "Running detection…"
                      : detectionSummary?.status === "completed"
                        ? "Re-run detection"
                        : detectionSummary?.status === "failed"
                          ? "Retry detection"
                          : "Run detection"}
                  </button>
                )}
            </div>
            {detectionSummary?.error_message && (
              <p className="mt-3 text-sm text-rose-300" role="alert">
                {detectionSummary.error_message}
              </p>
            )}
            {detectionError && (
              <p className="mt-3 text-sm text-rose-300" role="alert">
                {detectionError}
              </p>
            )}
            <p className="mt-3 text-xs text-slate-500">
              Severity reflects configured thresholds and observed evidence; it
              does not confirm malicious activity.
            </p>
            {detectionSummary?.status === "completed" && (
              <>
                <div className="mt-4 flex flex-wrap gap-2 text-xs">
                  {(["low", "medium", "high", "critical"] as const).map(
                    (severity) => (
                      <span
                        key={severity}
                        className={`rounded-full border px-2.5 py-1 ${severityClass(severity)}`}
                      >
                        {severity}: {detectionSummary.severity_counts[severity]}
                      </span>
                    ),
                  )}
                </div>
                <div className="mt-4 flex flex-wrap gap-4">
                  <label className="text-xs text-slate-400">
                    Severity
                    <select
                      aria-label="Filter findings by severity"
                      value={findingSeverity}
                      onChange={(event) => {
                        const value = event.currentTarget.value as
                          DetectionSeverity | "";
                        setFindingSeverity(value);
                        void loadFindingPage(0, value, findingRule);
                      }}
                      className="ml-2 rounded-md border border-line bg-ink px-2 py-1.5 text-slate-200"
                    >
                      <option value="">All severities</option>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </label>
                  <label className="text-xs text-slate-400">
                    Rule
                    <select
                      aria-label="Filter findings by rule"
                      value={findingRule}
                      onChange={(event) => {
                        const value = event.currentTarget.value;
                        setFindingRule(value);
                        void loadFindingPage(0, findingSeverity, value);
                      }}
                      className="ml-2 rounded-md border border-line bg-ink px-2 py-1.5 text-slate-200"
                    >
                      <option value="">All rules</option>
                      <option value="PORT_SCAN">Multi-port probing</option>
                      <option value="SYN_FLOOD_LIKE">
                        High SYN-only volume
                      </option>
                      <option value="EXCESSIVE_CONNECTION_ATTEMPTS">
                        Connection attempts
                      </option>
                    </select>
                  </label>
                </div>
              </>
            )}
            {findingLoading || detectionRunning ? (
              <p
                className="py-8 text-center text-sm text-slate-400"
                role="status"
              >
                {detectionRunning ? "Evaluating flows…" : "Loading findings…"}
              </p>
            ) : detectionSummary?.status === "processing" ? (
              <p
                className="py-8 text-center text-sm text-slate-400"
                role="status"
              >
                Detection is running for this analysis.
              </p>
            ) : detectionSummary?.status !== "completed" ? (
              <p className="py-8 text-center text-sm text-slate-500">
                Run detection after flow generation has completed.
              </p>
            ) : findings?.items.length ? (
              <>
                <div className="mt-4 space-y-3">
                  {findings.items.map((finding) => (
                    <article
                      key={finding.id}
                      className="rounded-xl border border-line bg-ink/60 p-4"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase ${severityClass(finding.severity)}`}
                        >
                          {finding.severity}
                        </span>
                        <h3 className="text-sm font-semibold">
                          {finding.rule_name}
                        </h3>
                        <span className="font-mono text-[10px] text-slate-500">
                          {finding.rule_id}
                        </span>
                      </div>
                      <p className="mt-2 text-sm leading-6 text-slate-300">
                        {finding.explanation}
                      </p>
                      <p className="mt-2 font-mono text-xs text-slate-400">
                        {finding.source_ip ?? "—"} →{" "}
                        {finding.destination_ip ?? "—"}
                        {finding.protocol_name
                          ? ` · ${finding.protocol_name}`
                          : ""}
                      </p>
                      <p className="mt-2 text-xs text-slate-500">
                        {finding.supporting_flow_count} supporting flow(s)
                        {finding.supporting_flow_sample_truncated
                          ? " · showing a sample of 100"
                          : ""}
                      </p>
                      <details className="mt-3 text-xs text-slate-400">
                        <summary className="cursor-pointer">Evidence</summary>
                        <pre className="mt-2 overflow-x-auto rounded-lg bg-black/20 p-3 font-mono text-[11px] leading-5">
                          {JSON.stringify(finding.evidence, null, 2)}
                        </pre>
                      </details>
                    </article>
                  ))}
                </div>
                <div className="mt-4 flex items-center justify-between">
                  <span className="text-xs text-slate-500">
                    {findings.total === 0 ? 0 : findingOffset + 1}–
                    {Math.min(
                      findingOffset + findings.items.length,
                      findings.total,
                    )}{" "}
                    of {findings.total}
                  </span>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={findingOffset === 0 || findingLoading}
                      onClick={() =>
                        void loadFindingPage(
                          Math.max(0, findingOffset - FINDING_PAGE_SIZE),
                        )
                      }
                      className="rounded-md border border-line px-3 py-2 text-xs text-slate-300 disabled:opacity-40"
                    >
                      Previous findings
                    </button>
                    <button
                      type="button"
                      disabled={
                        findingLoading ||
                        findingOffset + FINDING_PAGE_SIZE >= findings.total
                      }
                      onClick={() =>
                        void loadFindingPage(findingOffset + FINDING_PAGE_SIZE)
                      }
                      className="rounded-md border border-line px-3 py-2 text-xs text-slate-300 disabled:opacity-40"
                    >
                      Next findings
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <p className="py-8 text-center text-sm text-slate-500">
                No findings matched the selected rules and thresholds.
              </p>
            )}
          </section>
        )}

        {route.page === "ml" && (
          <div id="ml-detection">
            <MlAnalysisPanel
              analysis={routeAnalysis}
              analyses={analyses}
              onResultsChanged={refreshOverview}
            />
          </div>
        )}
        {route.page === "hybrid" && (
          <div id="hybrid-risk">
            <HybridAnalysisPanel
              analysis={routeAnalysis}
              detectionSummary={detectionSummary}
              onResultsChanged={refreshOverview}
            />
          </div>
        )}
        {route.page === "pipeline" && (
          <div id="analysis-pipeline">
            <PipelinePanel
              analysis={routeAnalysis}
              detectionSummary={detectionSummary}
              onResultsChanged={refreshOverview}
            />
          </div>
        )}
        {route.page === "analytics" && (
          <MonitoringAnalytics
            analyses={history}
            selectedAnalysis={null}
            selectedAnalysisId={parsedAnalysisId ?? undefined}
            onOpenAnalysis={(id) => navigate(`/analyses/${id}/flows`)}
            view="traffic"
          />
        )}
        {route.page === "events" && (
          <MonitoringAnalytics
            analyses={history}
            selectedAnalysis={null}
            onOpenAnalysis={(id) => navigate(`/analyses/${id}`)}
            view="events"
            onOpenEvent={(id) => navigate(`/events/${encodeURIComponent(id)}`)}
          />
        )}
        {route.page === "event" && (
          <MonitoringAnalytics
            analyses={history}
            selectedAnalysis={null}
            onOpenAnalysis={(id) => navigate(`/analyses/${id}`)}
            view="event"
            initialEventId={route.params.eventId}
          />
        )}
        {route.page === "compare" && (
          <MonitoringAnalytics
            analyses={history}
            selectedAnalysis={null}
            onOpenAnalysis={(id) => navigate(`/analyses/${id}`)}
            view="compare"
          />
        )}

        <footer className="mt-auto border-t border-line pt-4 text-xs text-slate-600">
          SENTINEL · Authorized network monitoring
        </footer>
      </div>
    </main>
  );
}

function Metric({
  label,
  value,
  detail,
}: {
  label: string;
  value: number | string;
  detail: string;
}) {
  return (
    <div className="rounded-xl border border-line bg-panel/70 p-4">
      <p className="text-xs text-slate-400">{label}</p>
      <p className="mt-2 text-2xl font-semibold tabular-nums">
        {value.toLocaleString()}
      </p>
      <p className="mt-1 text-[11px] text-slate-500">{detail}</p>
    </div>
  );
}

function SectionPlaceholder({
  id,
  title,
  message,
}: {
  id: string;
  title: string;
  message: string;
}) {
  return (
    <section
      id={id}
      className="scroll-mt-20 mt-6 rounded-2xl border border-dashed border-line bg-panel/40 p-6"
    >
      <h2 className="text-sm font-semibold">{title}</h2>
      <p className="mt-2 text-sm text-slate-500">{message}</p>
    </section>
  );
}

function Breadcrumbs({
  route,
  analysis,
}: {
  route: ReturnType<typeof resolveAppRoute>;
  analysis: Analysis | null;
}) {
  const analysisId = route.params.analysisId;
  return (
    <nav aria-label="Breadcrumb" className="py-4 text-xs text-slate-500">
      <ol className="flex flex-wrap items-center gap-2">
        <li>
          <Link className="hover:text-signal" to="/">
            Overview
          </Link>
        </li>
        {analysisId ? (
          <>
            <li aria-hidden="true">/</li>
            <li>
              <Link className="hover:text-signal" to="/analyses">
                Analyses
              </Link>
            </li>
            <li aria-hidden="true">/</li>
            <li>
              <Link
                className="hover:text-signal"
                to={`/analyses/${analysisId}`}
              >
                {analysis
                  ? `#${analysis.id} · ${analysis.original_filename}`
                  : `Analysis #${analysisId}`}
              </Link>
            </li>
          </>
        ) : route.page === "event" || route.page === "events" ? (
          <>
            <li aria-hidden="true">/</li>
            <li>
              <Link className="hover:text-signal" to="/events">
                Security events
              </Link>
            </li>
          </>
        ) : route.page !== "overview" ? (
          <>
            <li aria-hidden="true">/</li>
            <li aria-current="page" className="text-slate-300">
              {route.title}
            </li>
          </>
        ) : null}
        {analysisId && (
          <>
            <li aria-hidden="true">/</li>
            <li aria-current="page" className="text-slate-300">
              {route.title}
            </li>
          </>
        )}
        {route.page === "event" && (
          <>
            <li aria-hidden="true">/</li>
            <li aria-current="page" className="text-slate-300">
              Event details
            </li>
          </>
        )}
      </ol>
    </nav>
  );
}

function AnalysisNavigation({ analysisId }: { analysisId: number }) {
  const links = [
    ["Details", ""],
    ["Packets", "/packets"],
    ["Flows", "/flows"],
    ["Rules", "/rules"],
    ["ML", "/ml"],
    ["Hybrid", "/hybrid"],
    ["Pipeline", "/pipeline"],
    ["Traffic analytics", "/analytics"],
  ] as const;
  return (
    <nav
      aria-label={`Analysis ${analysisId} navigation`}
      className="-mt-1 mb-4 overflow-x-auto"
    >
      <ul className="flex min-w-max gap-2 text-xs">
        {links.map(([label, suffix]) => (
          <li key={label}>
            <NavLink
              end={!suffix}
              to={`/analyses/${analysisId}${suffix}`}
              className={({ isActive }) =>
                `rounded-md border px-3 py-2 ${isActive ? "border-signal/40 bg-signal/10 text-signal" : "border-line text-slate-400 hover:text-slate-100"}`
              }
            >
              {label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}

function AnalysisDetails({
  analysis,
  loading,
}: {
  analysis: Analysis | null;
  loading: boolean;
}) {
  if (!analysis) {
    return (
      <section
        className="rounded-2xl border border-line bg-panel/70 p-6"
        aria-live="polite"
      >
        <h1 className="text-xl font-semibold">Analysis details</h1>
        <p className="mt-2 text-sm text-slate-400">
          {loading ? "Loading analysis…" : "The analysis could not be loaded."}
        </p>
        <Link className="mt-4 inline-block text-sm text-signal" to="/analyses">
          Back to analysis history
        </Link>
      </section>
    );
  }
  return (
    <section className="rounded-2xl border border-line bg-panel/70 p-6">
      <p className="text-xs uppercase tracking-widest text-signal">
        Analysis details
      </p>
      <h1 className="mt-2 text-2xl font-semibold">
        {analysis.original_filename}
      </h1>
      <p className="mt-2 text-sm text-slate-400">
        Analysis #{analysis.id} · {analysis.capture_format.toUpperCase()} ·{" "}
        {formatBytes(analysis.file_size_bytes)} · {analysis.packet_count}{" "}
        packets
      </p>
      <div className="mt-5 flex flex-wrap gap-2 text-xs">
        <StatusBadge status={analysis.status} />
        <span className="rounded-full border border-line px-3 py-1.5 text-slate-300">
          {analysis.flow_count ?? "—"} flows ·{" "}
          {analysis.flow_generation_status.replaceAll("_", " ")}
        </span>
      </div>
      {analysis.error_message && (
        <p role="alert" className="mt-4 text-sm text-rose-300">
          {analysis.error_message}
        </p>
      )}
      <p className="mt-6 text-sm text-slate-400">
        Choose a section above to inspect this analysis and its persisted
        detection results.
      </p>
    </section>
  );
}

function StatusBadge({ status }: { status: Analysis["status"] }) {
  const styles = {
    pending: "border-amber-400/20 bg-amber-400/10 text-amber-200",
    processing: "border-sky-400/20 bg-sky-400/10 text-sky-200",
    completed: "border-signal/20 bg-signal/10 text-signal",
    failed: "border-rose-400/20 bg-rose-400/10 text-rose-200",
  }[status];
  return (
    <span
      className={`shrink-0 rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wide ${styles}`}
    >
      {status}
    </span>
  );
}

function endpoint(address: string | null, port: number | null): string {
  if (!address) return "—";
  if (port === null) return address;
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

function formatNumber(value: string | null): string {
  if (value === null) return "—";
  const number = Number(value);
  return Number.isFinite(number)
    ? number.toLocaleString(undefined, { maximumFractionDigits: 6 })
    : "—";
}

function severityClass(severity: DetectionSeverity): string {
  return {
    low: "border-sky-400/20 bg-sky-400/10 text-sky-200",
    medium: "border-amber-400/20 bg-amber-400/10 text-amber-200",
    high: "border-orange-400/20 bg-orange-400/10 text-orange-200",
    critical: "border-rose-400/20 bg-rose-400/10 text-rose-200",
  }[severity];
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB"];
  let value = bytes / 1024;
  let unit = units[0];
  for (let index = 1; value >= 1024 && index < units.length; index += 1) {
    value /= 1024;
    unit = units[index];
  }
  return `${value.toFixed(1)} ${unit}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "The request could not be completed.";
}
