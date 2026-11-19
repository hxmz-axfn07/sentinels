# SENTINEL

SENTINEL is a defensive network intrusion detection system for authorized offline PCAP/PCAPNG analysis. It supports packet metadata extraction, bidirectional flows, configurable rule findings, versioned Isolation Forest anomaly models, hybrid risk assessments, and explicit pipeline orchestration. Findings and risk scores support investigation; they are not proof of malicious activity.

## Requirements

- Python 3.12 (managed with [uv](https://docs.astral.sh/uv/))
- Node.js and npm
- Docker Engine with Docker Compose

## Local setup

1. Copy `.env.example` to `.env` and adjust the development credentials if needed.
2. Copy `frontend/.env.example` to `frontend/.env`; it points browser requests at the backend's IPv4 loopback address. The allowed browser origin remains `http://localhost:5174` as configured in `.env.example`.
3. Install backend dependencies and create the Python 3.12 environment:

   ```sh
   uv sync --project backend
   ```

4. Install frontend dependencies:

   ```sh
   cd frontend && npm ci && cd ..
   ```

5. Start MySQL:

   ```sh
   docker compose up -d db
   ```

6. Apply migrations and start the API:

   ```sh
   uv run --project backend alembic -c backend/alembic.ini upgrade head
   uv run --project backend uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8001 --reload
   ```

7. In another terminal, start the frontend:

   ```sh
   cd frontend && npm run dev -- --host localhost --port 5174
   ```

The dashboard is available at <http://localhost:5174>, the API at <http://localhost:8001>, and OpenAPI documentation at <http://localhost:8001/docs>. The MySQL container is exposed only on `127.0.0.1:3307`. Stop the foreground API and frontend with Ctrl+C in their respective terminals; `docker compose stop db` stops only SENTINEL's database container and preserves its volume. `docker compose down` also removes that container but preserves the named volume. Do not use `docker compose down -v` unless intentionally deleting the database data.

## Dashboard and overview

The overview at `GET /api/v1/dashboard/overview` is backed by persisted records and summarizes all stored analyses. Packet and flow totals include only completed processing stages. Rule counts use each analysis's latest completed rule run; ML counts use the latest persisted inference model per analysis; hybrid severity counts use the latest assessment per analysis to avoid double counting historical reruns. Coverage is displayed so absent rules or inference results are not mistaken for zero findings. Protocol distribution is a historical aggregate of generated flows, not live traffic. `GET /api/v1/dashboard/analyses?offset=0&limit=25` returns paginated analysis history with latest per-analysis stage status and results using batched queries. The UI links the overview, upload, history, packet, flow, rule, ML, hybrid, and pipeline sections.

## Checks

```sh
uv run --project backend pytest backend/tests
uv run --project backend ruff check backend
uv run --project backend ruff format --check backend
cd frontend && npm test -- --run && npm run lint && npm run format:check && npm run build
cd ..
uv run --project backend python scripts/render_report_diagrams.py
uv run --project backend python scripts/export_project_report.py
uv run --project backend python scripts/build_presentation.py
```

The Markdown academic report is the master copy. The `python-docx`, `python-pptx`, and Graphviz `dot` tools are development/documentation tools; they do not enter the runtime backend. Regenerate report diagrams before exporting the Word report and presentation.

## PCAP analysis

The upload form accepts capture contents recognized as classic PCAP (version 2.4, little or big endian, microsecond or nanosecond timestamps) and PCAPNG (section version 1.0). Validation uses file contents, not the filename or MIME type. The default maximum is 100 MiB and can be changed with `MAX_UPLOAD_SIZE_BYTES`. Uploads are staged in configured application storage using generated names; packet payloads are not persisted. Each accepted capture creates an analysis and ordered packet metadata rows.

The API exposes `GET /api/v1/analyses/limits`, `POST /api/v1/analyses/upload` (multipart field `file`), `GET /api/v1/analyses`, `GET /api/v1/analyses/{analysis_id}`, and paginated `GET /api/v1/analyses/{analysis_id}/packets?offset=0&limit=50`. Capture parsing runs synchronously during upload. A parser failure is recorded as a failed analysis and partial packet rows are cleared; the validated capture remains associated with that analysis for diagnosis or later handling.

Validation checks capture headers, record or block lengths, supported versions, and truncation before parsing with Scapy. PCAPNG support is limited to version 1.0 sections and recognized packet/interface block structures. These checks are structural safeguards, not a guarantee that every malformed packet payload can be interpreted. Treat uploaded captures as sensitive, and upload only traffic you are authorized to inspect. The storage directory must remain private and outside the frontend's public assets.

Schema updates are managed by Alembic. Revision `0002_capture_metadata` adds analysis lifecycle/file fields and the indexed `packet_metadata` table while retaining the Day 1 migration. Existing Day 1 analysis rows are backfilled as legacy records without capture files. Downgrading revision `0002` drops the packet table and capture metadata columns, so do not downgrade a database containing Day 2 analyses.

## Bidirectional flows

After a packet analysis completes, the dashboard can generate flows synchronously from its persisted packet metadata. `POST /api/v1/analyses/{analysis_id}/flows/generate` starts generation; repeated requests return the existing result. Retrieve paginated flows with `GET /api/v1/analyses/{analysis_id}/flows?offset=0&limit=50`, optionally filtered by `protocol` or IP `endpoint`, and retrieve one with `GET /api/v1/analyses/{analysis_id}/flows/{flow_id}`. The canonical endpoint ordering defines forward (endpoint A to B) and backward (B to A) counts; it does not infer client and server roles.

Flow statistics include packet and byte counts by direction, duration, packet-length and inter-arrival distributions, available TCP flag counts, and packet/byte rates. Rates are null for zero or unavailable duration. Missing timestamps and TCP flags remain unavailable in the corresponding features. The full key and feature definitions are in [docs/learn/flow-engine.md](docs/learn/flow-engine.md).

Alembic revision `0003_bidirectional_flows` adds flow records, analysis generation status, and packet flow assignments. Downgrading it deletes generated flow rows and packet assignments; only downgrade when intentionally discarding Day 3 results. Flow aggregation is not detection and does not classify traffic.

## Rule-based detection

After flow generation, run the three current rules synchronously with `POST /api/v1/analyses/{analysis_id}/detections/run`. Retrieve the latest run summary at `GET /api/v1/analyses/{analysis_id}/detection-summary`, findings at `GET /api/v1/analyses/{analysis_id}/findings?offset=0&limit=50`, or a finding at `GET /api/v1/analyses/{analysis_id}/findings/{finding_id}`. Findings accept `severity`, `rule_id`, and `run_id` filters. Same-configuration reruns reuse the completed run; changed configuration creates a new run and preserves the previous run for retrieval by `run_id`.

The rules identify multi-port probing, high capture-wide SYN-only packet volume, and distinct TCP flow tuples with observed SYN-only traffic. Default Low/Medium/High/Critical thresholds are respectively 5/10/25/50 distinct ports, 20/100/500/1000 SYN-only packets, and 10/25/50/100 TCP tuples with SYN-only traffic. These initial values are tunable starting points, not universal security limits. Rule enablement and thresholds can be set with the `DETECTION_CONFIG__...` variables documented in `.env.example`.

SYN-only and SYN+ACK counts are derived directionally from persisted packet flags. Since flag timestamps are not retained per packet in a flow, SYN activity is measured across the entire analysis rather than an invented time window. Connection-attempt findings do not establish successful handshakes. Findings link up to 100 supporting flow samples while preserving the exact support count. See [rule-based detection](docs/learn/rule-based-detection.md) for definitions, thresholds, tuning, and false-positive considerations.

Alembic revision `0004_rule_based_detection` adds directional handshake counts, detection run snapshots, findings, and supporting-flow links. Its downgrade removes findings and detection runs and drops those flow counts; do not downgrade if those results should be retained.

## Isolation Forest anomaly detection

Train an unsupervised model from explicitly selected completed analyses whose flows have been generated. The UI offers analyses containing at least 20 flows; the API requires at least 20 flows across the selected training set. Training is synchronous and creates a new model version each time. The default estimator uses 200 trees, `contamination=auto`, `max_samples=auto`, and random seed 42. These are reproducible starting settings, not validated detection thresholds. `ML_MAX_TRAINING_SAMPLES` limits the training population to 50,000 flows by default; larger datasets use deterministic reservoir sampling with the selected seed.

Models are stored outside the frontend under `MODEL_STORAGE_DIR` (default `storage/models`) and excluded from Git. The database stores feature schema, preprocessing, parameters, source analysis IDs, population/sample counts, scikit-learn version, and model version. Inference runs synchronously over flows in batches and is idempotent for an analysis/model pair. It stores `-decision_function` as the anomaly score: larger values are more unusual under that model, and scores are not probabilities. Existing model artifacts must remain in the managed storage directory and use the exact scikit-learn version recorded at training.

The API provides `POST /api/v1/ml/models/train`, `GET /api/v1/ml/models`, and `GET /api/v1/ml/models/{model_id}`. For completed analyses with generated flows, `POST /api/v1/analyses/{analysis_id}/ml/inference` accepts a model ID. Retrieve summaries at `GET /api/v1/analyses/{analysis_id}/ml/summary`, paginated results at `GET /api/v1/analyses/{analysis_id}/ml/results?model_id={model_id}&offset=0&limit=50`, and individual results with `GET /api/v1/analyses/{analysis_id}/ml/results/{result_id}?model_id={model_id}`. Results can be filtered by `prediction=anomaly` or `prediction=normal`.

The flow-v1 schema excludes identifiers, endpoints, timestamps, and labels. Missing numeric values use training medians and missingness indicators; nonnegative values are log1p transformed and constant transformed dimensions are removed. Full feature ordering, score interpretation, training-data caveats, persistence security, and limitations are documented in [docs/learn/isolation-forest.md](docs/learn/isolation-forest.md).

Alembic revision `0005_isolation_forest` adds model metadata and per-flow inference results. Downgrading removes those rows and is data-destructive. Application-generated model files are stored separately and are not removed by that database downgrade; preserve or remove them deliberately as a separate storage operation.

## Evaluation and academic materials

The `/evaluation` page shows persisted runs for the deterministic synthetic benchmark. The checked-in dataset manifest is [`docs/evaluation/dataset/manifest.json`](docs/evaluation/dataset/manifest.json), and the Day 11 persisted run #1 summary used in the final report and slides is [`docs/evaluation/results/run-1-summary.json`](docs/evaluation/results/run-1-summary.json). The dataset is recipe-based and is not representative of real-world traffic; its metrics are not production detection-accuracy claims.

To run the bounded synthetic evaluation, start the database and API, then submit a run (the default is seed 1101 and three repeats; the API allows one to five repeats):

```sh
curl -X POST http://127.0.0.1:8001/api/v1/evaluations \
  -H 'Content-Type: application/json' \
  -d '{"random_seed":1101,"repeat_count":3}'
```

Evaluation is synchronous. Retrieve persisted runs from `GET /api/v1/evaluations` or inspect them in the browser at `/evaluation`. Generated PCAPs and temporary artifacts are removed when a run ends; the persisted result is separate from operational analyses and incidents.

Project documentation:

- [Final project report (Markdown)](docs/project-report/report.md)
- [Final project report (Word)](docs/project-report/report.docx)
- [Project presentation](docs/project-report/SENTINEL-Presentation.pptx)
- [8–12 minute demonstration script](docs/project-report/demo-script.md)
- [Viva preparation](docs/project-report/viva-preparation.md)
- [Security audit and hardening](docs/learn/security-audit-and-quality-hardening.md)

The report, presentation, and demo guide contain visible placeholders for student and institutional details that must be completed before submission. SENTINEL remains an unauthenticated local single-user application; see the security documentation and report for limitations.
