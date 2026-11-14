# Day 1 foundation

SENTINEL consists of a FastAPI API, a React/TypeScript single-page application, and a MySQL database managed by Docker Compose. The frontend calls the API liveness endpoint and displays its connection state. The API readiness endpoint executes `SELECT 1` through SQLAlchemy so it reports whether the configured database can answer a query. Day 2 upload, validation, packet metadata, and API details are described in [PCAP ingestion and packet metadata](pcap-ingestion.md).

The backend reads settings from environment variables and the repository-root `.env` file. The example file contains local development defaults only. The database URL stays on the backend; the browser receives only the API base URL from its own Vite environment.

SQLAlchemy owns the `analyses` and `packet_metadata` mappings. Alembic owns schema changes: revision `0001_create_analyses` creates the foundation table and revision `0002_capture_metadata` adds capture lifecycle fields and packet metadata persistence. Downgrading revision 0001 drops analyses; downgrading revision 0002 drops Day 2 packet and capture metadata. Apply downgrades only when intentionally discarding affected data. Flow, event, and detection data are not processed or stored yet. Future schema migrations must preserve data and be reviewed as part of the corresponding milestone.

For startup instructions and verification commands, see the repository [README](../../README.md).
