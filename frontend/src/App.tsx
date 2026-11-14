import { useEffect, useState } from "react";
import { getHealth } from "./api/health";

type ServiceStatus = "checking" | "online" | "offline";

export default function App() {
  const [status, setStatus] = useState<ServiceStatus>("checking");

  useEffect(() => {
    let active = true;
    getHealth()
      .then(() => active && setStatus("online"))
      .catch(() => active && setStatus("offline"));
    return () => {
      active = false;
    };
  }, []);

  const statusLabel = {
    checking: "Checking API",
    online: "API online",
    offline: "API unavailable",
  }[status];

  return (
    <main className="min-h-screen bg-ink text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-6xl flex-col px-6 py-6 sm:px-10">
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
              className={`h-2 w-2 rounded-full ${status === "online" ? "bg-signal" : status === "offline" ? "bg-rose-400" : "bg-amber-300"}`}
              aria-hidden="true"
            />
            <span role="status" aria-live="polite">
              {statusLabel}
            </span>
          </div>
        </header>

        <section className="flex flex-1 flex-col justify-center py-20">
          <p className="mb-5 text-xs font-semibold uppercase tracking-[0.24em] text-signal">
            Security operations workspace
          </p>
          <h1 className="max-w-3xl text-4xl font-semibold leading-tight tracking-tight sm:text-6xl">
            See what is happening across your network.
          </h1>
          <p className="mt-6 max-w-2xl text-base leading-7 text-slate-400">
            The SENTINEL foundation is ready. Offline capture analysis and
            detection capabilities will be added in the next development
            milestones.
          </p>
          <div className="mt-12 grid gap-4 sm:grid-cols-3">
            {[
              ["01", "Capture analysis", "Not available yet"],
              ["02", "Detection engine", "Not available yet"],
              ["03", "Incident review", "Not available yet"],
            ].map(([number, title, detail]) => (
              <article
                key={number}
                className="rounded-2xl border border-line bg-panel/70 p-5"
              >
                <span className="text-xs font-medium tracking-widest text-slate-600">
                  {number}
                </span>
                <h2 className="mt-5 text-sm font-semibold text-slate-200">
                  {title}
                </h2>
                <p className="mt-2 text-xs text-slate-500">{detail}</p>
              </article>
            ))}
          </div>
        </section>
        <footer className="border-t border-line pt-4 text-xs text-slate-600">
          SENTINEL · Authorized network monitoring
        </footer>
      </div>
    </main>
  );
}
