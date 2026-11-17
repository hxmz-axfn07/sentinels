import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import IncidentManagement from "./IncidentManagement";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const baseIncident = {
  id: 3,
  title: "Synthetic review",
  description: "Synthetic fixture",
  status: "open",
  priority: "high",
  created_by: null,
  assigned_to: null,
  resolution_summary: null,
  resolved_at: null,
  created_at: "2026-11-16T00:00:00Z",
  updated_at: "2026-11-16T00:00:00Z",
  evidence_count: 0,
  analysis_ids: [],
};

describe("IncidentManagement", () => {
  it("shows persisted summary and filters the analyst incident list", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      return new Response(
        JSON.stringify(
          url.includes("/summary")
            ? {
                total: 1,
                status_counts: { open: 1 },
                priority_counts: { high: 1 },
              }
            : { items: [baseIncident], total: 1, offset: 0, limit: 25 },
        ),
        { status: 200 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MemoryRouter>
        <IncidentManagement initialEventIds={[]} onDraftConsumed={vi.fn()} />
      </MemoryRouter>,
    );
    expect(
      await screen.findByRole("link", { name: "Synthetic review" }),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Filter by incident status"), {
      target: { value: "open" },
    });
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(([url]) =>
          String(url).includes("status=open"),
        ),
      ).toBe(true),
    );
  });

  it("creates an incident from selected persisted findings", async () => {
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes("/events?"))
          return new Response(
            JSON.stringify({
              items: [
                {
                  event_id: "rule_finding:8",
                  event_type: "rule_finding",
                  analysis_id: 5,
                  original_filename: "SYNTHETIC-test.pcap",
                  explanation: "Synthetic rule evidence",
                  severity: "high",
                },
              ],
              total: 1,
              offset: 0,
              limit: 100,
            }),
            { status: 200 },
          );
        if (url.includes("/incidents?") && !url.includes("/summary"))
          return new Response(
            JSON.stringify({ items: [], total: 0, offset: 0, limit: 25 }),
            { status: 200 },
          );
        if (url.endsWith("/incidents") && init?.method === "POST")
          return new Response(
            JSON.stringify({
              ...baseIncident,
              id: 9,
              title: "Synthetic incident",
              evidence: [],
              notes: [],
              history: [],
            }),
            { status: 201 },
          );
        if (url.endsWith("/incidents"))
          return new Response(
            JSON.stringify({ items: [], total: 0, offset: 0, limit: 25 }),
            { status: 200 },
          );
        return new Response(
          JSON.stringify({ total: 0, status_counts: {}, priority_counts: {} }),
          { status: 200 },
        );
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MemoryRouter>
        <IncidentManagement
          initialEventIds={["rule_finding:8"]}
          onDraftConsumed={vi.fn()}
        />
      </MemoryRouter>,
    );
    const title = await screen.findByLabelText("Title");
    await waitFor(() =>
      expect((title as HTMLInputElement).value).toContain("Investigation:"),
    );
    expect(screen.getByLabelText("Priority")).toHaveValue("high");
    fireEvent.change(title, {
      target: { value: "Synthetic incident" },
    });
    fireEvent.click(
      screen.getAllByRole("button", { name: "Create incident" }).at(-1)!,
    );
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([url, init]) =>
            String(url).endsWith("/incidents") && init?.method === "POST",
        ),
      ).toBe(true),
    );
  });

  it("displays evidence and updates status and append-only notes", async () => {
    const detail = {
      ...baseIncident,
      evidence: [
        {
          id: 8,
          source_type: "rule_finding",
          source_id: 4,
          event_id: "rule_finding:4",
          analysis_id: 5,
          original_filename: "SYNTHETIC-detail.pcap",
          severity: "medium",
          anomaly_score: null,
          risk_score: null,
          source_ip: "192.0.2.5",
          destination_ip: "198.51.100.5",
          protocol: "TCP",
          explanation: "Synthetic persisted rule evidence",
          flow_ids: ["a".repeat(64)],
          model_id: null,
          model_version: null,
          evidence: { sampled: true },
          attached_at: baseIncident.created_at,
        },
      ],
      notes: [],
      history: [
        {
          id: 1,
          action: "incident_created",
          details: {},
          actor: null,
          created_at: baseIncident.created_at,
        },
      ],
      local_single_user: true,
    };
    let detailResponse = {
      ...detail,
      notes: [] as {
        id: number;
        body: string;
        created_by: null;
        created_at: string;
      }[],
    };
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/status")) {
          const body = JSON.parse(String(init?.body)) as {
            status: "investigating";
          };
          detailResponse = { ...detailResponse, status: body.status };
        }
        if (url.endsWith("/notes"))
          detailResponse = {
            ...detailResponse,
            notes: [
              {
                id: 1,
                body: "Synthetic note",
                created_by: null,
                created_at: baseIncident.created_at,
              },
            ],
          };
        if (url.endsWith("/notes"))
          return new Response(JSON.stringify(detailResponse.notes[0]), {
            status: 201,
          });
        return new Response(JSON.stringify(detailResponse), { status: 200 });
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MemoryRouter>
        <IncidentManagement
          incidentId="3"
          initialEventIds={[]}
          onDraftConsumed={vi.fn()}
        />
      </MemoryRouter>,
    );
    expect(
      await screen.findByText("Synthetic persisted rule evidence"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /SYNTHETIC-detail/ }),
    ).toHaveAttribute("href", "/analyses/5");
    fireEvent.change(screen.getByLabelText("Incident status"), {
      target: { value: "investigating" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Update status" }));
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([url, options]) =>
            String(url).endsWith("/status") && options?.method === "PATCH",
        ),
      ).toBe(true),
    );
    fireEvent.change(screen.getByLabelText("Add investigation note"), {
      target: { value: "Synthetic note" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add note" }));
    expect(await screen.findByText("Synthetic note")).toBeInTheDocument();
  });
});
