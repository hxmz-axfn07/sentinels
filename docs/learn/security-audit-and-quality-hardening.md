# SENTINEL Security Audit and Quality Hardening

## Scope and trust model

This review covered the offline PCAP/PCAPNG upload path, packet metadata and flow processing, rule/ML/hybrid services, pipeline and evaluation endpoints, incidents and their evidence relationships, API parameter bounds, filesystem storage, frontend rendering/routing, Alembic migrations, Compose configuration, dependencies, and repository contents. The application has no authentication or user identity system. It is a trusted local, single-user tool; it does not provide multi-user isolation or protect an exposed API from an untrusted network client.

| Boundary | Untrusted input or asset | Relevant control and verification |
| --- | --- | --- |
| Browser/API | IDs, filters, pagination, bodies, Origin header | Pydantic/FastAPI validation and bounded pagination; write requests with a mismatched browser `Origin` are rejected. Requests without `Origin` remain supported for local API clients. |
| Capture upload | Multipart bytes, filename, capture headers and packet records | Streaming size limit, generated temporary and final names, structural PCAP/PCAPNG checks, packet-count limit, metadata-only persistence, cleanup on handled failures. Synthetic malformed and limit cases are tested. |
| Database | Persisted analyses, findings, inference and incident references | SQLAlchemy parameter binding; foreign keys, unique constraints, composite evidence references, analysis-scoped queries and transactional incident updates. Migration tests use disposable SQLite databases. |
| Filesystem | Capture and model storage | Application-generated keys, managed roots, restrictive directory/file modes, resolved artifact-key checks, no public file route. Captures and artifacts are excluded from Git. |
| ML artifact | Joblib bytes | There is no model-upload endpoint. Inference loads only the generated key referenced by a ready model record, checks schema and scikit-learn versions, then validates the loaded pipeline structure. Joblib remains unsafe if an attacker can write to the managed artifact directory or replace trusted database records. |
| Evaluation | Synthetic recipes, temporary captures and results | Ground truth is recipe-derived, model training and evaluation samples are disjoint, runs have bounded repeat counts, and generated captures are temporary. Synthetic results are not production performance claims. |
| Deployment | Environment, Compose and listening ports | Compose binds MySQL to loopback and uses a persistent named volume. Runtime port and MySQL health checks were unavailable in this audit environment because no target ports were listening and Docker socket access was denied. |

## Implemented safeguards

Uploads are streamed in 64 KiB chunks into a server-generated `.part` file. The request middleware bounds multipart body size, and the file service independently bounds capture bytes. PCAP/PCAPNG structure is checked before packet parsing. The default configuration now limits one capture to 100,000 packet records; `MAX_CAPTURE_PACKETS` can lower or raise that bound to at most 1,000,000. Over-limit captures return HTTP 413 before analysis rows or final capture files are created. The limit bounds work, but it does not promise a particular latency or memory ceiling for every capture.

The managed capture directory is set to mode `0700` when an upload is staged; temporary files created by `mkstemp` are mode `0600` and retain that mode after the atomic rename. Model storage is already restricted to `0700`, with artifact files at `0600`. Permission checks are verified on the current POSIX test filesystem; other filesystems may implement permissions differently.

State-changing browser requests (`POST`, `PATCH`, `PUT`, and `DELETE`) carrying an `Origin` different from `FRONTEND_ORIGIN` now receive HTTP 403. This is a cross-site request defense for browser requests, not authentication or authorization. Requests that omit `Origin` are intentionally still usable by local non-browser clients; deployment must therefore bind the service to a trusted interface and restrict network access.

Incident create/update schemas now trim titles and reject whitespace-only values before persistence. Existing incident evidence references are checked against source rows and constrained with relational keys; duplicate attachments are idempotent. Notes are appended, status changes are validated, and history records the changes. The actor remains null because the application has no identity system.

The chart-heavy analytics/event and evaluation pages are loaded on demand. This reduces the initial production JavaScript bundle while retaining React Router deep links and page loading states.

## Resource and query bounds

- Capture upload: default 100 MiB and 100,000 packets; packet ceiling is configurable up to 1,000,000.
- Packet, flow, analysis, findings, ML result, hybrid, and pipeline list endpoints use bounded pagination (typically at most 200 rows; incident, event, and evaluation lists at most 100).
- Flow generation, rule scans, ML fit sampling, and inference use batches. ML training defaults to a 50,000-flow sample; model requests bound estimator count and analysis ID count.
- Hybrid assessment rejects more than 5,000 rule findings plus anomalous-flow records.
- Evaluation requests bound repetitions to five and use a fixed, small synthetic manifest.
- Analytics endpoints use SQL aggregates and fixed top-N lists; comparison is limited to five analyses.

Upload processing, flow generation, detection, inference, hybrid assessment, and evaluation remain synchronous. Limits reduce exposure but no worker queue or server-side operation timeout exists. A slow request can occupy an API worker or outlast a client/proxy timeout. Failed analysis captures are retained with their failed analysis record for traceability; there is no retention or deletion workflow, so an operator must monitor managed-storage disk usage.

## Audit findings and disposition

| Severity | Finding | Remediation / verification |
| --- | --- | --- |
| Medium, fixed | A valid small-file capture could contain a very large number of tiny packet records and cause unbounded database and downstream work. | Added configurable packet-count enforcement during structural inspection. API and parser tests cover PCAP and PCAPNG over-limit rejection and cleanup. |
| Medium, fixed | Existing capture directories could retain permissive modes even though individual temporary files were private. | Upload staging now applies directory mode `0700`; tests assert directory `0700` and stored file `0600` on POSIX. |
| Medium, fixed | CORS alone does not prevent a cross-site HTML form from submitting a simple write request. | Added an Origin check for browser state-changing methods. Tests reject an unrelated origin and accept the configured frontend origin. This does not replace authentication. |
| Low, fixed | A whitespace-only incident title passed minimum-length validation, then became empty after service trimming. | Pydantic validators normalize and reject blank create/update titles; API tests cover both. |
| High, accepted limitation | There is no authentication, authorization, or per-user object ownership. Any client able to reach the API can read or mutate stored analyses and incidents. | Keep the application on a trusted local interface. Multi-user/network deployment requires a separately designed authentication and authorization milestone. The Origin guard is not a substitute. |
| Medium, accepted operational risk | Synchronous processing and retained captures can consume worker time and disk over repeated use. | Byte, packet, batch, sample, evidence, repeat, and pagination bounds exist; no request timeout, background worker, or automatic storage retention is implemented. Monitor disk and expose the service only locally. |
| Informational | Joblib deserialization can execute code if the artifact file itself is attacker-controlled. | No user model-upload route exists; only internally generated, mode-restricted artifacts under managed storage are loaded. The local application account and database remain trusted. |

## Verification and limitations

The focused upload/parser/incident suite passed 35 tests, and the full backend suite passed 142 tests. The frontend suite passed 55 tests after a timing-sensitive test was corrected to wait for its asynchronously loaded model option and enabled action. Ruff check and format passed across the backend tree. ESLint and Prettier passed; the production build passed and route-level chunks reduced the entry chunk from 706.93 kB to 257.09 kB, with no chunk exceeding Vite's 500 kB advisory threshold.

The initial port probe found no application services, while MySQL on loopback 3307 remained available. The backend and Vite frontend were started on loopback ports 8001 and 5174 for verification and were left running. `/health/ready` returned database-ready, and the persisted dashboard API returned two analyses, 36 packets, 36 flows, two rule findings, 12 anomaly indicators, and one hybrid assessment. Chromium screenshots were captured after waiting for API data and visually inspected for Overview, Upload, Analysis details, Analysis traffic analytics, Security events, Incidents, and Evaluation. The nested analytics path rendered through direct URL entry. `docker compose config -q` passed; Docker daemon access was denied, so Compose runtime state was not inspected. Alembic current/check against MySQL returned revision `0009_evaluation_runs` at head with no schema drift; a disposable SQLite database also upgraded through `0009` and reported no drift. `pip-audit --local` found no known backend vulnerabilities. `npm audit` reported two moderate advisories affecting the installed React Router 6.30.6 line; the affected server hydration path is unused, and app navigation destinations are generated from fixed routes or validated/encoded IDs. npm's available fix requires a major upgrade to React Router 7, so it was not applied during this focused hardening change. The current app has no authentication, TLS termination, distributed worker, capture retention policy, or large-capture stress validation. Passing tests do not establish that SENTINEL is secure or production-ready.
