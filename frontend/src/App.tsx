import { useEffect, useState, type FormEvent } from "react";
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
import { generateFlows, getFlows, type FlowList } from "./api/flows";

const PACKET_PAGE_SIZE = 50;
const FLOW_PAGE_SIZE = 50;
type ServiceStatus = "checking" | "online" | "offline";

export default function App() {
  const [serviceStatus, setServiceStatus] = useState<ServiceStatus>("checking");
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [limits, setLimits] = useState<UploadLimits | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState<Analysis | null>(
    null,
  );
  const [packets, setPackets] = useState<PacketList | null>(null);
  const [flows, setFlows] = useState<FlowList | null>(null);
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
      })
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, []);

  async function selectAnalysis(id: number, pageOffset = 0) {
    setPacketLoading(true);
    setPageError(null);
    try {
      const [analysis, packetPage] = await Promise.all([
        getAnalysis(id),
        getPackets(id, pageOffset, PACKET_PAGE_SIZE),
      ]);
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
    } catch (error) {
      setPageError(errorMessage(error));
    } finally {
      setPacketLoading(false);
      setFlowLoading(false);
    }
  }

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
      setSelectedAnalysis(result);
      setOffset(0);
      setFlows(null);
      setFlowOffset(0);
      const firstPage = await getPackets(result.id, 0, PACKET_PAGE_SIZE);
      setPackets(firstPage);
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

  const statusLabel = {
    checking: "Checking API",
    online: "API online",
    offline: "API unavailable",
  }[serviceStatus];
  const tooLarge = Boolean(
    selectedFile && limits && selectedFile.size > limits.max_upload_size_bytes,
  );

  return (
    <main className="min-h-screen bg-ink text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-7xl flex-col px-6 py-6 sm:px-10">
        <header className="flex items-center justify-between border-b border-line pb-5">
          <a
            className="flex items-center gap-3"
            href="/"
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
          </a>
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

        <section className="py-10">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-signal">
            Offline capture analysis
          </p>
          <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">
            PCAP ingestion
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
            Upload an authorized PCAP or PCAPNG capture. SENTINEL records packet
            metadata without storing packet payloads.
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
                {uploadProgress === null ? "Upload and analyze" : "Processing…"}
              </button>
            </form>
          </section>

          <section className="rounded-2xl border border-line bg-panel/70 p-5 sm:p-6">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold">Analyses</h2>
              <span className="text-xs text-slate-500">
                {analyses.length} shown
              </span>
            </div>
            {loading ? (
              <p className="mt-5 text-sm text-slate-400">Loading analyses…</p>
            ) : analyses.length === 0 ? (
              <p className="mt-5 rounded-xl border border-dashed border-line p-6 text-center text-sm text-slate-500">
                No captures have been analyzed yet.
              </p>
            ) : (
              <ul className="mt-4 divide-y divide-line">
                {analyses.map((analysis) => (
                  <li key={analysis.id}>
                    <button
                      className="flex w-full items-center justify-between gap-4 py-3 text-left hover:text-signal"
                      onClick={() => void selectAnalysis(analysis.id)}
                      type="button"
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">
                          {analysis.original_filename}
                        </span>
                        <span className="mt-1 block text-xs text-slate-500">
                          {analysis.capture_format.toUpperCase()} ·{" "}
                          {analysis.packet_count} packets
                        </span>
                      </span>
                      <StatusBadge status={analysis.status} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        {pageError && (
          <p className="mt-5 text-sm text-rose-300" role="alert">
            {pageError}
          </p>
        )}

        {selectedAnalysis && (
          <section className="mt-6 rounded-2xl border border-line bg-panel/70 p-5 sm:p-6">
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

        {selectedAnalysis && (
          <section className="mt-6 rounded-2xl border border-line bg-panel/70 p-5 sm:p-6">
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
                            {flow.duration_seconds ?? "—"}
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

        <footer className="mt-auto border-t border-line pt-4 text-xs text-slate-600">
          SENTINEL · Authorized network monitoring
        </footer>
      </div>
    </main>
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
