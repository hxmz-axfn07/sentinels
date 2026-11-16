import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { OverviewAnalysis } from "../api/dashboard";
import {
  compareAnalyses,
  getSecurityEvent,
  getSecurityEvents,
  getTrafficAnalytics,
  type AnalysisComparison,
  type SecurityEventDetail,
  type SecurityEventPage,
  type TrafficAnalytics,
} from "../api/analytics";

const PAGE_SIZE = 20;
const chartColors = ["#34d399", "#60a5fa", "#fbbf24", "#a78bfa", "#fb7185"];

export default function MonitoringAnalytics({
  analyses,
  selectedAnalysis,
  onOpenAnalysis,
}: {
  analyses: OverviewAnalysis[];
  selectedAnalysis: OverviewAnalysis | null;
  onOpenAnalysis: (id: number) => void;
}) {
  const selectedAnalysisId = selectedAnalysis?.id;
  const initialId = selectedAnalysis?.id ?? analyses[0]?.id ?? "";
  const [analysisId, setAnalysisId] = useState<number | "">(initialId);
  const [traffic, setTraffic] = useState<TrafficAnalytics | null>(null);
  const [trafficLoading, setTrafficLoading] = useState(false);
  const [trafficError, setTrafficError] = useState<string | null>(null);
  const [events, setEvents] = useState<SecurityEventPage | null>(null);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [eventType, setEventType] = useState("");
  const [severity, setSeverity] = useState("");
  const [protocol, setProtocol] = useState("");
  const [recordedAfter, setRecordedAfter] = useState("");
  const [recordedBefore, setRecordedBefore] = useState("");
  const [eventOffset, setEventOffset] = useState(0);
  const [detail, setDetail] = useState<SecurityEventDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [comparisonIds, setComparisonIds] = useState<number[]>([]);
  const [comparison, setComparison] = useState<AnalysisComparison | null>(null);
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);

  useEffect(() => {
    if (analysisId === "") {
      setTraffic(null);
      return;
    }
    let active = true;
    setTrafficLoading(true);
    setTrafficError(null);
    getTrafficAnalytics(analysisId)
      .then((result) => active && setTraffic(result))
      .catch((error: unknown) => active && setTrafficError(message(error)))
      .finally(() => active && setTrafficLoading(false));
    return () => {
      active = false;
    };
  }, [analysisId]);

  useEffect(() => {
    if (selectedAnalysisId !== undefined) setAnalysisId(selectedAnalysisId);
  }, [selectedAnalysisId]);

  useEffect(() => {
    let active = true;
    setEventsLoading(true);
    setEventsError(null);
    getSecurityEvents({
      offset: eventOffset,
      limit: PAGE_SIZE,
      analysis_id: analysisId === "" ? undefined : analysisId,
      event_type: eventType || undefined,
      severity: severity || undefined,
      protocol: protocol || undefined,
      recorded_after: toUtcIso(recordedAfter),
      recorded_before: toUtcIso(recordedBefore),
    })
      .then((result) => active && setEvents(result))
      .catch((error: unknown) => active && setEventsError(message(error)))
      .finally(() => active && setEventsLoading(false));
    return () => {
      active = false;
    };
  }, [
    analysisId,
    eventOffset,
    eventType,
    protocol,
    recordedAfter,
    recordedBefore,
    severity,
  ]);

  const comparisonChoices = useMemo(
    () => analyses.filter((analysis) => analysis.status === "completed"),
    [analyses],
  );
  async function loadComparison() {
    if (comparisonIds.length < 2) return;
    setComparisonLoading(true);
    setComparisonError(null);
    try {
      setComparison(await compareAnalyses(comparisonIds));
    } catch (error) {
      setComparisonError(message(error));
    } finally {
      setComparisonLoading(false);
    }
  }

  async function openEvent(id: string) {
    setDetailLoading(true);
    setDetailError(null);
    setDetail(null);
    try {
      setDetail(await getSecurityEvent(id));
    } catch (error) {
      setDetailError(message(error));
    } finally {
      setDetailLoading(false);
    }
  }

  return (
    <>
      <section id="traffic-analytics" className="scroll-mt-24 py-8">
        <SectionHeading
          eyebrow="Historical capture analytics"
          title="Traffic analytics"
          description="Aggregates are calculated from persisted packet metadata and flows for one selected capture. This is not live monitoring."
        />
        <label className="mt-5 block max-w-lg text-xs text-slate-400">
          Selected analysis
          <select
            aria-label="Selected analysis for traffic analytics"
            className="mt-2 w-full rounded-lg border border-line bg-panel px-3 py-2 text-sm text-slate-200"
            value={analysisId}
            onChange={(event) =>
              setAnalysisId(
                event.currentTarget.value
                  ? Number(event.currentTarget.value)
                  : "",
              )
            }
          >
            <option value="">Choose a completed analysis</option>
            {analyses
              .filter((analysis) => analysis.status === "completed")
              .map((analysis) => (
                <option key={analysis.id} value={analysis.id}>
                  #{analysis.id} · {analysis.original_filename}
                </option>
              ))}
          </select>
        </label>
        {trafficLoading ? (
          <StateText>Loading traffic analytics…</StateText>
        ) : null}
        {trafficError ? <StateText error>{trafficError}</StateText> : null}
        {!trafficLoading && !trafficError && !traffic ? (
          <StateText>
            Select a completed analysis to view its capture data.
          </StateText>
        ) : null}
        {traffic ? (
          <>
            <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <Metric
                label="Packets"
                value={traffic.packet_count.toLocaleString()}
                detail={`${traffic.timestamped_packet_count.toLocaleString()} timestamped`}
              />
              <Metric
                label="Captured bytes"
                value={formatBytes(traffic.total_bytes)}
                detail="Sum of stored packet lengths"
              />
              <Metric
                label="Flows"
                value={traffic.flow_count?.toLocaleString() ?? "—"}
                detail={
                  traffic.flow_generation_status === "completed"
                    ? "Persisted bidirectional flows"
                    : "Flow generation not complete"
                }
              />
              <Metric
                label="Capture duration"
                value={
                  traffic.duration_seconds === null
                    ? "—"
                    : `${traffic.duration_seconds.toFixed(2)} s`
                }
                detail={
                  traffic.packets_per_second === null
                    ? "Rates unavailable or incomplete timestamps"
                    : `${traffic.packets_per_second.toFixed(2)} packets/s`
                }
              />
            </div>
            <div className="mt-5 grid gap-5 xl:grid-cols-2">
              <ChartCard
                title="Protocol distribution"
                note="Packet counts from this capture"
              >
                {traffic.protocols.length ? (
                  <div
                    className="h-72"
                    role="img"
                    aria-label="Protocol packet distribution chart"
                  >
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={traffic.protocols}
                        margin={{ top: 10, right: 10, left: -18, bottom: 5 }}
                      >
                        <CartesianGrid stroke="#25313b" vertical={false} />
                        <XAxis dataKey="protocol" stroke="#94a3b8" />
                        <YAxis stroke="#94a3b8" allowDecimals={false} />
                        <Tooltip
                          contentStyle={{
                            background: "#111a22",
                            border: "1px solid #34424d",
                            borderRadius: 8,
                          }}
                        />
                        <Bar
                          dataKey="packet_count"
                          name="Packets"
                          radius={[5, 5, 0, 0]}
                        >
                          {traffic.protocols.map((item, index) => (
                            <Cell
                              key={item.protocol}
                              fill={chartColors[index % chartColors.length]}
                            />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <EmptyText>
                    No packet protocol metadata is available.
                  </EmptyText>
                )}
                <div className="mt-3 flex flex-wrap gap-2">
                  {traffic.protocols.map((item) => (
                    <span
                      key={item.protocol}
                      className="rounded-md border border-line px-2 py-1 text-xs text-slate-300"
                    >
                      {item.protocol}: {item.packet_count} ·{" "}
                      {item.packet_percentage.toFixed(1)}%
                    </span>
                  ))}
                </div>
              </ChartCard>
              <ChartCard
                title="Capture timeline"
                note={`Packet timestamps · ${traffic.timeline_bucket_seconds ?? "—"} second bucket width`}
              >
                {traffic.timeline.length ? (
                  <div
                    className="h-72"
                    role="img"
                    aria-label="Packet volume over capture timestamp"
                  >
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart
                        data={traffic.timeline}
                        margin={{ top: 10, right: 10, left: -18, bottom: 5 }}
                      >
                        <CartesianGrid stroke="#25313b" vertical={false} />
                        <XAxis
                          dataKey="bucket_start_epoch"
                          stroke="#94a3b8"
                          tickFormatter={(value: number) =>
                            new Date(value * 1000).toLocaleTimeString()
                          }
                          minTickGap={28}
                        />
                        <YAxis stroke="#94a3b8" allowDecimals={false} />
                        <Tooltip
                          labelFormatter={(value) =>
                            new Date(Number(value) * 1000).toLocaleString()
                          }
                          contentStyle={{
                            background: "#111a22",
                            border: "1px solid #34424d",
                            borderRadius: 8,
                          }}
                        />
                        <Area
                          type="stepAfter"
                          dataKey="packet_count"
                          name="Packets"
                          stroke="#34d399"
                          fill="#34d399"
                          fillOpacity={0.16}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <EmptyText>
                    {traffic.timestamped_packet_count === 0
                      ? "Timeline unavailable because packet timestamps are missing."
                      : "No timestamped packet observations are available."}
                  </EmptyText>
                )}
                {traffic.unavailable_timestamp_packet_count > 0 ? (
                  <p className="mt-2 text-xs text-amber-300">
                    {traffic.unavailable_timestamp_packet_count} packets have no
                    timestamp and are excluded from the timeline.
                  </p>
                ) : null}
              </ChartCard>
            </div>
            <div className="mt-5 grid gap-5 xl:grid-cols-2">
              <ChartCard
                title="Directional traffic"
                note="Flow totals; shown only when flow generation is complete"
              >
                {traffic.forward_bytes === null ? (
                  <EmptyText>
                    Directional flow data is unavailable until flows are
                    generated.
                  </EmptyText>
                ) : (
                  <div className="grid grid-cols-2 gap-3">
                    <Metric
                      label="Forward"
                      value={formatBytes(traffic.forward_bytes)}
                      detail={`${traffic.forward_packets?.toLocaleString()} packets`}
                    />
                    <Metric
                      label="Backward"
                      value={formatBytes(traffic.backward_bytes ?? 0)}
                      detail={`${traffic.backward_packets?.toLocaleString()} packets`}
                    />
                  </div>
                )}
              </ChartCard>
              <ChartCard
                title="Packet length distribution"
                note="Persisted packet lengths in bytes"
              >
                {traffic.packet_length_distribution.length ? (
                  <div className="h-56">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={traffic.packet_length_distribution}>
                        <CartesianGrid stroke="#25313b" vertical={false} />
                        <XAxis dataKey="bucket" stroke="#94a3b8" />
                        <YAxis stroke="#94a3b8" allowDecimals={false} />
                        <Tooltip
                          contentStyle={{
                            background: "#111a22",
                            border: "1px solid #34424d",
                          }}
                        />
                        <Bar
                          dataKey="packet_count"
                          name="Packets"
                          fill="#60a5fa"
                          radius={[4, 4, 0, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <EmptyText>No packet length data is available.</EmptyText>
                )}
              </ChartCard>
            </div>
            <div className="mt-5 grid gap-5 xl:grid-cols-2">
              <EndpointTable
                title="Top source endpoints"
                rows={traffic.top_source_endpoints}
              />
              <EndpointTable
                title="Top destination endpoints"
                rows={traffic.top_destination_endpoints}
              />
            </div>
            <div className="mt-5 grid gap-5 xl:grid-cols-2">
              <FlowTable
                title="Top flows by bytes"
                rows={traffic.top_flows_by_bytes}
              />
              <FlowTable
                title="Top flows by packets"
                rows={traffic.top_flows_by_packets}
              />
            </div>
          </>
        ) : null}
      </section>

      <section id="security-events" className="scroll-mt-24 py-8">
        <SectionHeading
          eyebrow="Persisted detections"
          title="Security event feed"
          description="Rule findings, per-flow ML anomaly indicators, and hybrid assessments remain distinct event types. Recorded timestamps refer to the source record, not capture time."
        />
        <div className="mt-5 flex flex-wrap items-end gap-3 rounded-xl border border-line bg-panel/60 p-4">
          <Filter
            label="Event type"
            value={eventType}
            onChange={(value) => {
              setEventType(value);
              setEventOffset(0);
            }}
            options={[
              ["", "All event types"],
              ["rule_finding", "Rule finding"],
              ["ml_anomaly", "ML anomaly indicator"],
              ["hybrid_assessment", "Hybrid assessment"],
            ]}
          />
          <label className="min-w-48 text-xs text-slate-400">
            Recorded from (local time)
            <input
              aria-label="Events recorded from"
              type="datetime-local"
              className="mt-2 w-full rounded-md border border-line bg-ink px-3 py-2 text-sm"
              value={recordedAfter}
              onChange={(event) => {
                setRecordedAfter(event.currentTarget.value);
                setEventOffset(0);
              }}
            />
          </label>
          <label className="min-w-48 text-xs text-slate-400">
            Recorded through (local time)
            <input
              aria-label="Events recorded through"
              type="datetime-local"
              className="mt-2 w-full rounded-md border border-line bg-ink px-3 py-2 text-sm"
              value={recordedBefore}
              onChange={(event) => {
                setRecordedBefore(event.currentTarget.value);
                setEventOffset(0);
              }}
            />
          </label>
          <Filter
            label="Severity"
            value={severity}
            onChange={(value) => {
              setSeverity(value);
              setEventOffset(0);
            }}
            options={[
              ["", "All severities"],
              ["informational", "Informational"],
              ["low", "Low"],
              ["medium", "Medium"],
              ["high", "High"],
              ["critical", "Critical"],
            ]}
          />
          <Filter
            label="Protocol"
            value={protocol}
            onChange={(value) => {
              setProtocol(value);
              setEventOffset(0);
            }}
            options={[
              ["", "All protocols"],
              ["TCP", "TCP traffic"],
              ["UDP", "UDP traffic"],
              ["ICMP", "ICMP traffic"],
            ]}
          />
          <label className="min-w-56 text-xs text-slate-400">
            Analysis
            <select
              className="mt-2 w-full rounded-md border border-line bg-ink px-3 py-2 text-sm"
              value={analysisId}
              onChange={(event) => {
                setAnalysisId(
                  event.currentTarget.value
                    ? Number(event.currentTarget.value)
                    : "",
                );
                setEventOffset(0);
              }}
              aria-label="Filter events by analysis"
            >
              <option value="">All analyses</option>
              {analyses.map((analysis) => (
                <option key={analysis.id} value={analysis.id}>
                  #{analysis.id} · {analysis.original_filename}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="rounded-md border border-line px-3 py-2 text-xs hover:border-signal"
            onClick={() => {
              setEventType("");
              setSeverity("");
              setProtocol("");
              setRecordedAfter("");
              setRecordedBefore("");
              setAnalysisId("");
              setEventOffset(0);
            }}
          >
            Reset filters
          </button>
        </div>
        {eventsLoading ? <StateText>Loading security events…</StateText> : null}
        {eventsError ? <StateText error>{eventsError}</StateText> : null}
        {!eventsLoading && !eventsError && events?.items.length === 0 ? (
          <EmptyText>
            No persisted security events match these filters.
          </EmptyText>
        ) : null}
        {events?.items.length ? (
          <div className="mt-4 overflow-x-auto rounded-xl border border-line">
            <table className="w-full min-w-[850px] text-left text-xs">
              <thead className="bg-panel text-slate-400">
                <tr>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Severity / score</th>
                  <th className="px-4 py-3">Analysis</th>
                  <th className="px-4 py-3">Endpoints</th>
                  <th className="px-4 py-3">Recorded time</th>
                  <th className="px-4 py-3">Explanation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line bg-panel/50">
                {events.items.map((item) => (
                  <tr key={item.event_id} className="text-slate-300">
                    <td className="px-4 py-3">
                      {eventLabel(item.event_type)}
                      {item.protocol ? (
                        <span className="mt-1 block text-slate-500">
                          {item.protocol}
                        </span>
                      ) : null}
                    </td>
                    <td className="px-4 py-3">
                      <Severity severity={item.severity} />
                      {item.risk_score ? (
                        <span className="ml-2 tabular-nums">
                          {item.risk_score}/100
                        </span>
                      ) : null}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        type="button"
                        className="text-left hover:text-signal"
                        onClick={() => onOpenAnalysis(item.analysis_id)}
                      >
                        #{item.analysis_id} · {item.original_filename}
                      </button>
                    </td>
                    <td className="px-4 py-3 font-mono">
                      {item.source_ip ?? "—"}
                      <span className="text-slate-600"> → </span>
                      {item.destination_ip ?? "—"}
                    </td>
                    <td className="px-4 py-3">
                      <time dateTime={item.recorded_at}>
                        {new Date(item.recorded_at).toLocaleString()}
                      </time>
                      <span className="mt-1 block text-slate-500">
                        {item.timestamp_label}
                      </span>
                    </td>
                    <td className="max-w-sm px-4 py-3">
                      <p className="line-clamp-2">{item.explanation}</p>
                      <button
                        type="button"
                        className="mt-1 text-signal hover:underline"
                        onClick={() => void openEvent(item.event_id)}
                      >
                        Inspect evidence
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {events && events.total > PAGE_SIZE ? (
          <Pagination
            offset={eventOffset}
            total={events.total}
            limit={PAGE_SIZE}
            loading={eventsLoading}
            onChange={setEventOffset}
          />
        ) : null}
        {detailLoading ? <StateText>Loading event evidence…</StateText> : null}
        {detailError ? <StateText error>{detailError}</StateText> : null}
        {detail ? (
          <div className="mt-5 rounded-xl border border-signal/30 bg-panel p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-widest text-slate-500">
                  {eventLabel(detail.event.event_type)} ·{" "}
                  {detail.event.related_reference}
                </p>
                <h3 className="mt-2 text-lg font-semibold">
                  {detail.event.explanation}
                </h3>
                <p className="mt-2 text-xs text-slate-400">
                  Analysis #{detail.event.analysis_id} ·{" "}
                  {detail.event.timestamp_label}:{" "}
                  {new Date(detail.event.recorded_at).toLocaleString()}
                </p>
              </div>
              <button
                type="button"
                className="rounded-md border border-line px-3 py-2 text-xs"
                onClick={() => setDetail(null)}
              >
                Close details
              </button>
            </div>
            <pre className="mt-4 max-h-80 overflow-auto rounded-lg bg-ink p-4 text-xs text-emerald-100">
              {JSON.stringify(detail.evidence, null, 2)}
            </pre>
            <div className="mt-3 flex flex-wrap gap-3 text-xs">
              {detail.related_flow_ids.map((id) => (
                <a
                  key={id}
                  href="#bidirectional-flows"
                  className="text-signal hover:underline"
                  onClick={() => onOpenAnalysis(detail.event.analysis_id)}
                >
                  Open related flows · {id.slice(0, 12)}…
                </a>
              ))}
              {detail.related_flow_ids.length === 0 ? (
                <button
                  type="button"
                  className="text-signal hover:underline"
                  onClick={() => onOpenAnalysis(detail.event.analysis_id)}
                >
                  Open analysis #{detail.event.analysis_id}
                </button>
              ) : null}
            </div>
          </div>
        ) : null}
      </section>

      <section id="analysis-comparison" className="scroll-mt-24 py-8">
        <SectionHeading
          eyebrow="Independent analysis records"
          title="Analysis comparison"
          description="Compare two to five completed captures. Missing stages remain unavailable rather than being shown as zero."
        />
        <div className="mt-5 rounded-xl border border-line bg-panel/60 p-4">
          <p className="text-xs text-slate-400">
            Select completed analyses (2–5)
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {comparisonChoices.map((analysis) => (
              <label
                key={analysis.id}
                className={`flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-xs ${comparisonIds.includes(analysis.id) ? "border-signal/60 bg-signal/10 text-slate-100" : "border-line text-slate-400"}`}
              >
                <input
                  type="checkbox"
                  checked={comparisonIds.includes(analysis.id)}
                  disabled={
                    !comparisonIds.includes(analysis.id) &&
                    comparisonIds.length >= 5
                  }
                  onChange={(event) =>
                    setComparisonIds((current) =>
                      event.target.checked
                        ? [...current, analysis.id].slice(-5)
                        : current.filter((id) => id !== analysis.id),
                    )
                  }
                />
                #{analysis.id} · {analysis.original_filename}
              </label>
            ))}
          </div>
          <button
            type="button"
            disabled={comparisonIds.length < 2 || comparisonLoading}
            onClick={() => void loadComparison()}
            className="mt-4 rounded-lg bg-signal px-4 py-2 text-xs font-semibold text-ink disabled:opacity-40"
          >
            {comparisonLoading ? "Comparing…" : "Compare selected"}
          </button>
        </div>
        {comparisonError ? (
          <StateText error>{comparisonError}</StateText>
        ) : null}
        {comparison ? (
          <>
            <ul className="mt-3 space-y-1 text-xs text-amber-200">
              {comparison.metric_limitations.map((item) => (
                <li key={item}>• {item}</li>
              ))}
            </ul>
            <div className="mt-4 overflow-x-auto rounded-xl border border-line">
              <table className="w-full min-w-[760px] text-left text-xs">
                <thead className="bg-panel text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Analysis</th>
                    <th className="px-4 py-3">Packets</th>
                    <th className="px-4 py-3">Bytes</th>
                    <th className="px-4 py-3">Flows</th>
                    <th className="px-4 py-3">Rules by severity</th>
                    <th className="px-4 py-3">ML anomalies</th>
                    <th className="px-4 py-3">Hybrid risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {comparison.items.map((item) => (
                    <tr key={item.analysis_id}>
                      <td className="px-4 py-3">
                        <button
                          type="button"
                          className="text-left hover:text-signal"
                          onClick={() => onOpenAnalysis(item.analysis_id)}
                        >
                          #{item.analysis_id} · {item.original_filename}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        {item.packet_count.toLocaleString()}
                      </td>
                      <td className="px-4 py-3">
                        {formatBytes(item.total_bytes)}
                      </td>
                      <td className="px-4 py-3">
                        {item.flow_count?.toLocaleString() ?? "Not generated"}
                      </td>
                      <td className="px-4 py-3">
                        {item.rule_findings_by_severity
                          ? Object.entries(item.rule_findings_by_severity)
                              .map(([key, value]) => `${key}: ${value}`)
                              .join(" · ") || "0 findings"
                          : "Not run"}
                      </td>
                      <td className="px-4 py-3">
                        {item.ml_anomaly_count?.toLocaleString() ?? "Not run"}
                        {item.ml_model_id ? ` · model ${item.ml_model_id}` : ""}
                      </td>
                      <td className="px-4 py-3">
                        {item.hybrid_risk_score === null
                          ? "Not assessed"
                          : `${item.hybrid_risk_score} · ${item.hybrid_severity}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : null}
      </section>
    </>
  );
}

function SectionHeading({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string;
  title: string;
  description: string;
}) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-[0.22em] text-signal">
        {eyebrow}
      </p>
      <h2 className="mt-2 text-2xl font-semibold tracking-tight">{title}</h2>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
        {description}
      </p>
    </div>
  );
}

function ChartCard({
  title,
  note,
  children,
}: {
  title: string;
  note: string;
  children: ReactNode;
}) {
  return (
    <section className="rounded-2xl border border-line bg-panel/70 p-5">
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="mt-1 text-xs text-slate-500">{note}</p>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function Metric({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-xl border border-line bg-panel/70 p-4">
      <p className="text-xs text-slate-400">{label}</p>
      <p className="mt-2 text-xl font-semibold tabular-nums">{value}</p>
      <p className="mt-1 text-[11px] text-slate-500">{detail}</p>
    </div>
  );
}

function EndpointTable({
  title,
  rows,
}: {
  title: string;
  rows: TrafficAnalytics["top_source_endpoints"];
}) {
  return (
    <section className="rounded-xl border border-line bg-panel/70 p-4">
      <h3 className="text-sm font-semibold">{title}</h3>
      {rows.length ? (
        <ul className="mt-3 divide-y divide-line text-xs">
          {rows.map((row) => (
            <li key={row.address} className="flex justify-between gap-3 py-2">
              <span className="font-mono text-slate-300">{row.address}</span>
              <span className="text-slate-500">
                {row.packet_count} pkts · {formatBytes(row.total_bytes)}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyText>No endpoint records available.</EmptyText>
      )}
    </section>
  );
}

function FlowTable({
  title,
  rows,
}: {
  title: string;
  rows: TrafficAnalytics["top_flows_by_bytes"];
}) {
  return (
    <section className="rounded-xl border border-line bg-panel/70 p-4">
      <h3 className="text-sm font-semibold">{title}</h3>
      {rows.length ? (
        <ul className="mt-3 divide-y divide-line text-xs">
          {rows.map((row) => (
            <li key={row.flow_id} className="py-2">
              <span className="font-mono text-slate-300">
                {row.endpoint_a ?? "—"} → {row.endpoint_b ?? "—"}
              </span>
              <span className="mt-1 block text-slate-500">
                {row.protocol} · {row.total_packets} packets ·{" "}
                {formatBytes(row.total_bytes)} · forward{" "}
                {formatBytes(row.forward_bytes)} / backward{" "}
                {formatBytes(row.backward_bytes)}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyText>No generated flows are available.</EmptyText>
      )}
    </section>
  );
}

function Filter({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: [string, string][];
}) {
  return (
    <label className="min-w-40 text-xs text-slate-400">
      {label}
      <select
        className="mt-2 block w-full rounded-md border border-line bg-ink px-3 py-2 text-sm text-slate-200"
        value={value}
        onChange={(event) => onChange(event.currentTarget.value)}
      >
        {options.map(([option, text]) => (
          <option key={option} value={option}>
            {text}
          </option>
        ))}
      </select>
    </label>
  );
}

function Pagination({
  offset,
  total,
  limit,
  loading,
  onChange,
}: {
  offset: number;
  total: number;
  limit: number;
  loading: boolean;
  onChange: (value: number) => void;
}) {
  return (
    <div className="mt-3 flex items-center justify-end gap-2 text-xs text-slate-400">
      <span>
        {offset + 1}–{Math.min(offset + limit, total)} of {total}
      </span>
      <button
        type="button"
        disabled={offset === 0 || loading}
        onClick={() => onChange(Math.max(0, offset - limit))}
        className="rounded border border-line px-3 py-2 disabled:opacity-40"
      >
        Previous
      </button>
      <button
        type="button"
        disabled={offset + limit >= total || loading}
        onClick={() => onChange(offset + limit)}
        className="rounded border border-line px-3 py-2 disabled:opacity-40"
      >
        Next
      </button>
    </div>
  );
}

function Severity({ severity }: { severity: string | null }) {
  if (!severity)
    return (
      <span className="rounded border border-line px-2 py-1 text-slate-400">
        Unrated
      </span>
    );
  const color =
    severity === "critical" || severity === "high"
      ? "border-rose-500/40 text-rose-300"
      : severity === "medium"
        ? "border-amber-500/40 text-amber-300"
        : "border-slate-500/40 text-slate-300";
  return (
    <span className={`rounded border px-2 py-1 uppercase ${color}`}>
      {severity}
    </span>
  );
}

function StateText({
  children,
  error = false,
}: {
  children: ReactNode;
  error?: boolean;
}) {
  return (
    <p
      role={error ? "alert" : "status"}
      className={`mt-4 text-sm ${error ? "text-rose-300" : "text-slate-400"}`}
    >
      {children}
    </p>
  );
}

function EmptyText({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-lg border border-dashed border-line p-5 text-center text-xs text-slate-500">
      {children}
    </p>
  );
}

function eventLabel(type: string): string {
  return (
    {
      rule_finding: "Rule finding",
      ml_anomaly: "ML anomaly indicator",
      hybrid_assessment: "Hybrid assessment",
    }[type] ?? type
  );
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let amount = value / 1024;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount.toFixed(1)} ${units[index]}`;
}

function message(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "The request could not be completed.";
}

function toUtcIso(value: string): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}
