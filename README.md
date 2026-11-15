# SENTINEL

SENTINEL is a defensive network intrusion detection system. The Day 3 milestone supports secure offline PCAP and PCAPNG ingestion, packet metadata extraction, and synchronous bidirectional flow generation. Intrusion detection is not implemented yet.

## Requirements

- Python 3.12 (managed with [uv](https://docs.astral.sh/uv/))
- Node.js and npm
- Docker Engine with Docker Compose

## Local setup

1. Copy `.env.example` to `.env` and adjust the development credentials if needed.
2. Optionally copy `frontend/.env.example` to `frontend/.env` to override the API base URL.
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
   cd frontend && npm run dev -- --host 127.0.0.1 --port 5174
   ```

The dashboard is available at <http://localhost:5174>, the API at <http://localhost:8001>, and OpenAPI documentation at <http://localhost:8001/docs>. The MySQL container is exposed on `127.0.0.1:3307`. `docker compose down` stops only this project's database container; its named volume remains. Use `docker compose down -v` only when intentionally deleting the local database data.

## Checks

```sh
uv run --project backend pytest backend/tests
uv run --project backend ruff check backend
uv run --project backend ruff format --check backend
cd frontend && npm test -- --run && npm run lint && npm run build
```

## PCAP analysis

The upload form accepts capture contents recognized as classic PCAP (version 2.4, little or big endian, microsecond or nanosecond timestamps) and PCAPNG (section version 1.0). Validation uses file contents, not the filename or MIME type. The default maximum is 100 MiB and can be changed with `MAX_UPLOAD_SIZE_BYTES`. Uploads are staged in configured application storage using generated names; packet payloads are not persisted. Each accepted capture creates an analysis and ordered packet metadata rows.

The API exposes `GET /api/v1/analyses/limits`, `POST /api/v1/analyses/upload` (multipart field `file`), `GET /api/v1/analyses`, `GET /api/v1/analyses/{analysis_id}`, and paginated `GET /api/v1/analyses/{analysis_id}/packets?offset=0&limit=50`. Capture parsing runs synchronously during upload. A parser failure is recorded as a failed analysis and partial packet rows are cleared; the validated capture remains associated with that analysis for diagnosis or later handling.

Validation checks capture headers, record or block lengths, supported versions, and truncation before parsing with Scapy. PCAPNG support is limited to version 1.0 sections and recognized packet/interface block structures. These checks are structural safeguards, not a guarantee that every malformed packet payload can be interpreted. Treat uploaded captures as sensitive, and upload only traffic you are authorized to inspect. The storage directory must remain private and outside the frontend's public assets.

Schema updates are managed by Alembic. Revision `0002_capture_metadata` adds analysis lifecycle/file fields and the indexed `packet_metadata` table while retaining the Day 1 migration. Existing Day 1 analysis rows are backfilled as legacy records without capture files. Downgrading revision `0002` drops the packet table and capture metadata columns, so do not downgrade a database containing Day 2 analyses.

## Bidirectional flows

After a packet analysis completes, the dashboard can generate flows synchronously from its persisted packet metadata. `POST /api/v1/analyses/{analysis_id}/flows/generate` starts generation; repeated requests return the existing result. Retrieve paginated flows with `GET /api/v1/analyses/{analysis_id}/flows?offset=0&limit=50`, optionally filtered by `protocol` or IP `endpoint`, and retrieve one with `GET /api/v1/analyses/{analysis_id}/flows/{flow_id}`. The canonical endpoint ordering defines forward (endpoint A to B) and backward (B to A) counts; it does not infer client and server roles.

Flow statistics include packet and byte counts by direction, duration, packet-length and inter-arrival distributions, available TCP flag counts, and packet/byte rates. Rates are null for zero or unavailable duration. Missing timestamps and TCP flags remain unavailable in the corresponding features. The full key and feature definitions are in [docs/learn/flow-engine.md](docs/learn/flow-engine.md).

Alembic revision `0003_bidirectional_flows` adds flow records, analysis generation status, and packet flow assignments. Downgrading it deletes generated flow rows and packet assignments; only downgrade when intentionally discarding Day 3 results. Flow aggregation is not detection and does not classify traffic.
