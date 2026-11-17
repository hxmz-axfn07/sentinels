import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  addIncidentNote,
  attachEvidence,
  createIncident,
  detachEvidence,
  getIncident,
  getIncidentSummary,
  getIncidents,
  updateIncident,
  updateIncidentStatus,
  type IncidentDetail,
  type IncidentPriority,
  type IncidentStatus,
} from "../api/incidents";
import { getSecurityEvents, type SecurityEvent } from "../api/analytics";

const statuses: IncidentStatus[] = [
  "open",
  "acknowledged",
  "investigating",
  "resolved",
  "closed",
];
const priorities: IncidentPriority[] = ["low", "medium", "high", "critical"];

export default function IncidentManagement({
  incidentId,
  initialEventIds,
  onDraftConsumed,
}: {
  incidentId?: string;
  initialEventIds: string[];
  onDraftConsumed: () => void;
}) {
  const navigate = useNavigate();
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [list, setList] = useState<Awaited<
    ReturnType<typeof getIncidents>
  > | null>(null);
  const [summary, setSummary] = useState<Awaited<
    ReturnType<typeof getIncidentSummary>
  > | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [priorityFilter, setPriorityFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState<IncidentPriority>("medium");
  const [selected, setSelected] = useState<string[]>(initialEventIds);
  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState("");
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (incidentId) setDetail(await getIncident(Number(incidentId)));
      else {
        const [page, counts] = await Promise.all([
          getIncidents({
            search: search || undefined,
            status: statusFilter || undefined,
            priority: priorityFilter || undefined,
          }),
          getIncidentSummary(),
        ]);
        setList(page);
        setSummary(counts);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Incident data could not be loaded.",
      );
      setDetail(null);
    } finally {
      setLoading(false);
    }
  }, [incidentId, priorityFilter, search, statusFilter]);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  useEffect(() => {
    if (!showCreate) return;
    getSecurityEvents({ limit: 100 })
      .then((page) => setEvents(page.items))
      .catch((err) =>
        setError(
          err instanceof Error ? err.message : "Events could not be loaded.",
        ),
      );
  }, [showCreate]);
  useEffect(() => {
    setSelected(initialEventIds);
    if (initialEventIds.length) setShowCreate(true);
  }, [initialEventIds]);
  useEffect(() => {
    if (!initialEventIds.length || !events.length) return;
    const selectedEvents = events.filter((event) =>
      initialEventIds.includes(event.event_id),
    );
    if (!selectedEvents.length) return;
    const sources = [
      ...new Set(
        selectedEvents.map((event) => event.event_type.replaceAll("_", " ")),
      ),
    ];
    const analysisIds = [
      ...new Set(selectedEvents.map((event) => event.analysis_id)),
    ];
    setTitle(
      (current) =>
        current ||
        `Investigation: ${sources.join(", ")} · analysis ${analysisIds.join(", ")}`,
    );
    setDescription(
      (current) =>
        current ||
        `Analyst review of persisted ${sources.join(", ")} evidence from analysis ${analysisIds.map((id) => `#${id}`).join(", ")}. This evidence does not by itself confirm an attack.`,
    );
    const severityRank: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    };
    const strongest = selectedEvents
      .map((event) => event.severity)
      .filter((value): value is string => Boolean(value))
      .sort((a, b) => (severityRank[b] ?? 0) - (severityRank[a] ?? 0))[0];
    if (strongest && strongest in severityRank)
      setPriority(strongest as IncidentPriority);
  }, [events, initialEventIds]);

  async function submitCreate(event: FormEvent) {
    event.preventDefault();
    if (incidentId) {
      if (selected.length)
        void mutate(async () => {
          const updated = await attachEvidence(Number(incidentId), selected);
          setDetail(updated);
          setShowCreate(false);
        });
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const created = await createIncident({
        title: title.trim(),
        description: description.trim(),
        priority,
        event_ids: selected,
      });
      onDraftConsumed();
      setShowCreate(false);
      navigate(`/incidents/${created.id}`);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Incident could not be created.",
      );
    } finally {
      setSaving(false);
    }
  }
  async function mutate(action: () => Promise<unknown>) {
    setSaving(true);
    setError(null);
    try {
      await action();
      await refresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "The incident update failed.",
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="py-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-signal">
            Analyst investigation
          </p>
          <h1 className="mt-2 text-3xl font-semibold">
            {incidentId
              ? (detail?.title ?? `Incident #${incidentId}`)
              : "Incidents"}
          </h1>
          <p className="mt-2 text-sm text-slate-400">
            Incidents are analyst-managed investigations; detection findings
            remain unchanged.
          </p>
        </div>
        {incidentId ? (
          <button
            onClick={() => navigate("/incidents")}
            className="rounded-lg border border-line px-3 py-2 text-sm"
          >
            All incidents
          </button>
        ) : (
          <button
            onClick={() => setShowCreate(true)}
            className="rounded-lg bg-signal px-3 py-2 text-sm font-semibold text-ink"
          >
            Create incident
          </button>
        )}
      </div>
      {error && (
        <p
          role="alert"
          className="mt-4 rounded-lg border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200"
        >
          {error}
        </p>
      )}
      {loading ? (
        <p role="status" className="mt-6 text-sm text-slate-400">
          Loading incident records…
        </p>
      ) : null}
      {!incidentId && summary && list && !loading && (
        <>
          <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {[
              ["Total", summary.total],
              ...statuses.map((s) => [s, summary.status_counts[s] ?? 0]),
            ].map(([label, value]) => (
              <div
                key={label}
                className="rounded-xl border border-line bg-panel/70 p-4"
              >
                <p className="text-xs capitalize text-slate-400">{label}</p>
                <p className="mt-2 text-2xl font-semibold">{value}</p>
              </div>
            ))}
          </div>
          <div
            className="mt-3 flex flex-wrap gap-2"
            aria-label="Incident priority distribution"
          >
            {priorities.map((level) => (
              <span
                key={level}
                className="rounded-full border border-line px-3 py-1 text-xs capitalize text-slate-300"
              >
                {level}: {summary.priority_counts[level] ?? 0}
              </span>
            ))}
          </div>
          <div className="mt-5 flex flex-wrap gap-3">
            <input
              aria-label="Search incidents"
              value={search}
              onChange={(e) => setSearch(e.currentTarget.value)}
              placeholder="Search title"
              className="rounded-lg border border-line bg-panel px-3 py-2 text-sm"
            />
            <select
              aria-label="Filter by incident status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.currentTarget.value)}
              className="rounded-lg border border-line bg-panel px-3 py-2 text-sm"
            >
              <option value="">All statuses</option>
              {statuses.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
            <select
              aria-label="Filter by incident priority"
              value={priorityFilter}
              onChange={(e) => setPriorityFilter(e.currentTarget.value)}
              className="rounded-lg border border-line bg-panel px-3 py-2 text-sm"
            >
              <option value="">All priorities</option>
              {priorities.map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </div>
          {list.items.length ? (
            <div className="mt-4 overflow-x-auto rounded-xl border border-line">
              <table className="w-full min-w-[700px] text-left text-sm">
                <thead className="bg-panel text-slate-400">
                  <tr>
                    {[
                      "Incident",
                      "Status",
                      "Priority",
                      "Evidence",
                      "Analyses",
                      "Updated",
                    ].map((x) => (
                      <th key={x} className="px-4 py-3">
                        {x}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {list.items.map((item) => (
                    <tr key={item.id}>
                      <td className="px-4 py-3">
                        <Link
                          className="text-signal hover:underline"
                          to={`/incidents/${item.id}`}
                        >
                          {item.title}
                        </Link>
                        <p className="mt-1 max-w-sm truncate text-xs text-slate-500">
                          {item.description}
                        </p>
                      </td>
                      <td className="px-4 py-3 capitalize">{item.status}</td>
                      <td className="px-4 py-3 capitalize">{item.priority}</td>
                      <td className="px-4 py-3">{item.evidence_count}</td>
                      <td className="px-4 py-3">
                        {item.analysis_ids.map((id) => (
                          <Link
                            key={id}
                            className="mr-2 text-signal"
                            to={`/analyses/${id}`}
                          >
                            #{id}
                          </Link>
                        ))}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {new Date(item.updated_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : !loading ? (
            <div className="mt-5 rounded-xl border border-dashed border-line p-8 text-sm text-slate-400">
              No incidents match this view. Create an incident from selected
              persisted security evidence.
            </div>
          ) : null}
        </>
      )}
      {incidentId && detail && !loading && (
        <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
          <div className="space-y-5">
            <section className="rounded-xl border border-line bg-panel/70 p-5">
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="text-xs text-slate-400">
                  Title
                  <input
                    aria-label="Incident title"
                    className="mt-1 w-full rounded border border-line bg-ink p-2 text-sm text-slate-100"
                    value={detail.title}
                    onChange={(e) =>
                      setDetail({ ...detail, title: e.currentTarget.value })
                    }
                  />
                </label>
                <label className="text-xs text-slate-400">
                  Priority
                  <select
                    aria-label="Incident priority"
                    className="mt-1 w-full rounded border border-line bg-ink p-2 text-sm text-slate-100"
                    value={detail.priority}
                    onChange={(e) => {
                      const value = e.currentTarget.value as IncidentPriority;
                      setDetail({ ...detail, priority: value });
                      void mutate(() =>
                        updateIncident(detail.id, { priority: value }),
                      );
                    }}
                  >
                    {priorities.map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                </label>
              </div>
              <label className="mt-3 block text-xs text-slate-400">
                Description
                <textarea
                  aria-label="Incident description"
                  className="mt-1 w-full rounded border border-line bg-ink p-2 text-sm text-slate-100"
                  rows={3}
                  value={detail.description}
                  onChange={(e) =>
                    setDetail({ ...detail, description: e.currentTarget.value })
                  }
                />
              </label>
              <button
                disabled={saving}
                onClick={() =>
                  void mutate(() =>
                    updateIncident(detail.id, {
                      title: detail.title,
                      description: detail.description,
                    }),
                  )
                }
                className="mt-3 rounded border border-line px-3 py-2 text-xs disabled:opacity-50"
              >
                Save details
              </button>
              <div className="mt-4 flex flex-wrap items-end gap-3">
                <label className="text-xs text-slate-400">
                  Status
                  <select
                    aria-label="Incident status"
                    className="mt-1 block rounded border border-line bg-ink p-2 text-sm text-slate-100"
                    value={detail.status}
                    onChange={(e) =>
                      setDetail({
                        ...detail,
                        status: e.currentTarget.value as IncidentStatus,
                      })
                    }
                  >
                    {statuses.map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
                {detail.status !== "resolved" &&
                detail.status !== "closed" ? null : (
                  <label className="text-xs text-slate-400">
                    Resolution summary
                    <input
                      aria-label="Resolution summary"
                      value={resolution}
                      onChange={(e) => setResolution(e.currentTarget.value)}
                      className="mt-1 block rounded border border-line bg-ink p-2 text-sm text-slate-100"
                    />
                  </label>
                )}
                <button
                  disabled={saving}
                  onClick={() =>
                    void mutate(() =>
                      updateIncidentStatus(
                        detail.id,
                        detail.status,
                        detail.status === "resolved" ? resolution : undefined,
                      ),
                    )
                  }
                  className="rounded bg-signal px-3 py-2 text-xs font-semibold text-ink disabled:opacity-50"
                >
                  Update status
                </button>
              </div>
              <p className="mt-3 text-xs text-slate-500">
                Created {new Date(detail.created_at).toLocaleString()} · updated{" "}
                {new Date(detail.updated_at).toLocaleString()} · single-user
                mode; analyst identity is not configured.
              </p>
            </section>
            <section className="rounded-xl border border-line bg-panel/70 p-5">
              <div className="flex justify-between">
                <h2 className="font-semibold">
                  Related evidence ({detail.evidence.length})
                </h2>
                <button
                  onClick={() => {
                    setSelected([]);
                    setShowCreate(true);
                  }}
                  className="text-xs text-signal"
                >
                  Attach evidence
                </button>
              </div>
              {detail.evidence.length ? (
                <ul className="mt-3 divide-y divide-line">
                  {detail.evidence.map((ev) => (
                    <li key={ev.id} className="py-3">
                      <div className="flex flex-wrap justify-between gap-2">
                        <span className="text-xs uppercase text-signal">
                          {ev.source_type.replaceAll("_", " ")} · {ev.event_id}
                        </span>
                        <button
                          className="text-xs text-rose-300"
                          onClick={() =>
                            void mutate(() => detachEvidence(detail.id, ev.id))
                          }
                        >
                          Detach
                        </button>
                      </div>
                      <p className="mt-1 text-sm">{ev.explanation}</p>
                      <details className="mt-2 text-xs text-slate-400">
                        <summary className="cursor-pointer text-signal">
                          View stored evidence
                        </summary>
                        <pre className="mt-2 max-h-60 overflow-auto whitespace-pre-wrap rounded bg-ink p-3">
                          {JSON.stringify(ev.evidence, null, 2)}
                        </pre>
                      </details>
                      <p className="mt-1 text-xs text-slate-400">
                        Analysis{" "}
                        <Link
                          className="text-signal"
                          to={`/analyses/${ev.analysis_id}`}
                        >
                          #{ev.analysis_id} · {ev.original_filename}
                        </Link>
                        {ev.severity ? ` · ${ev.severity}` : ""}
                        {ev.risk_score ? ` · risk ${ev.risk_score}/100` : ""}
                        {ev.anomaly_score
                          ? ` · model score ${ev.anomaly_score} (not probability)`
                          : ""}
                      </p>
                      {ev.flow_ids.map((flow) => (
                        <Link
                          key={flow}
                          className="mr-3 mt-2 inline-block text-xs text-signal"
                          to={`/analyses/${ev.analysis_id}/flows`}
                        >
                          Flow {flow.slice(0, 12)}…
                        </Link>
                      ))}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-3 text-sm text-slate-500">
                  No evidence is attached.
                </p>
              )}
            </section>
            <section className="rounded-xl border border-line bg-panel/70 p-5">
              <h2 className="font-semibold">Investigation notes</h2>
              <form
                className="mt-3 flex gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (note.trim())
                    void mutate(async () => {
                      await addIncidentNote(detail.id, note);
                      setNote("");
                    });
                }}
              >
                <input
                  aria-label="Add investigation note"
                  value={note}
                  onChange={(e) => setNote(e.currentTarget.value)}
                  className="min-w-0 flex-1 rounded border border-line bg-ink px-3 py-2 text-sm"
                  placeholder="Record an observation"
                />
                <button
                  disabled={saving || !note.trim()}
                  className="rounded bg-signal px-3 text-xs font-semibold text-ink disabled:opacity-50"
                >
                  Add note
                </button>
              </form>
              <ul className="mt-3 space-y-3">
                {detail.notes.map((n) => (
                  <li key={n.id} className="border-l-2 border-signal/50 pl-3">
                    <p className="text-sm">{n.body}</p>
                    <time className="text-xs text-slate-500">
                      {new Date(n.created_at).toLocaleString()}
                    </time>
                  </li>
                ))}
              </ul>
            </section>
          </div>
          <section className="h-fit rounded-xl border border-line bg-panel/70 p-5">
            <h2 className="font-semibold">Investigation history</h2>
            <ol className="mt-3 space-y-4">
              {detail.history.map((h) => (
                <li key={h.id} className="border-l border-line pl-3">
                  <p className="text-sm">{h.action.replaceAll("_", " ")}</p>
                  <p className="mt-1 break-words text-xs text-slate-400">
                    {JSON.stringify(h.details)}
                  </p>
                  <time className="text-xs text-slate-500">
                    {new Date(h.created_at).toLocaleString()}
                  </time>
                </li>
              ))}
            </ol>
          </section>
        </div>
      )}
      {showCreate && (
        <div className="fixed inset-0 z-30 grid place-items-center bg-black/70 p-4">
          <form
            onSubmit={submitCreate}
            className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-line bg-panel p-5 shadow-xl"
          >
            <div className="flex justify-between">
              <h2 className="text-lg font-semibold">
                {incidentId ? "Attach evidence" : "Create incident"}
              </h2>
              <button
                type="button"
                aria-label="Close"
                onClick={() => {
                  setShowCreate(false);
                  if (initialEventIds.length) onDraftConsumed();
                }}
              >
                ×
              </button>
            </div>
            {!incidentId && (
              <>
                <label className="mt-4 block text-xs text-slate-400">
                  Title
                  <input
                    required
                    minLength={1}
                    maxLength={200}
                    value={title}
                    onChange={(e) => setTitle(e.currentTarget.value)}
                    className="mt-1 w-full rounded border border-line bg-ink p-2 text-sm text-slate-100"
                  />
                </label>
                <label className="mt-3 block text-xs text-slate-400">
                  Description
                  <textarea
                    value={description}
                    onChange={(e) => setDescription(e.currentTarget.value)}
                    className="mt-1 w-full rounded border border-line bg-ink p-2 text-sm text-slate-100"
                  />
                </label>
                <label className="mt-3 block text-xs text-slate-400">
                  Priority
                  <select
                    value={priority}
                    onChange={(e) =>
                      setPriority(e.currentTarget.value as IncidentPriority)
                    }
                    className="mt-1 block rounded border border-line bg-ink p-2 text-sm text-slate-100"
                  >
                    {priorities.map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                </label>
              </>
            )}
            <p className="mt-4 text-xs text-slate-400">
              Select persisted evidence. ML anomaly indicators are not confirmed
              attacks.
            </p>
            <div className="mt-2 max-h-64 overflow-auto rounded border border-line">
              {events.map((ev) => (
                <label
                  key={ev.event_id}
                  className="flex cursor-pointer gap-3 border-b border-line p-3 text-xs"
                >
                  <input
                    type="checkbox"
                    checked={selected.includes(ev.event_id)}
                    onChange={(e) =>
                      setSelected((current) =>
                        e.currentTarget.checked
                          ? [...current, ev.event_id]
                          : current.filter((id) => id !== ev.event_id),
                      )
                    }
                  />
                  <span>
                    <span className="text-slate-200">
                      {ev.event_type.replaceAll("_", " ")} ·{" "}
                      {ev.severity ?? "Unrated"} · analysis #{ev.analysis_id}
                    </span>
                    <span className="mt-1 block text-slate-500">
                      {ev.explanation}
                    </span>
                  </span>
                </label>
              ))}
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                className="rounded border border-line px-3 py-2 text-xs"
                onClick={() => setShowCreate(false)}
              >
                Cancel
              </button>
              <button
                disabled={saving || !selected.length}
                className="rounded bg-signal px-3 py-2 text-xs font-semibold text-ink disabled:opacity-50"
              >
                {saving
                  ? "Saving…"
                  : incidentId
                    ? "Attach selected"
                    : "Create incident"}
              </button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}
