# Day 1 foundation

SENTINEL currently consists of a FastAPI API, a React/TypeScript single-page application, and a MySQL database managed by Docker Compose. The frontend calls the API liveness endpoint and displays its connection state. The API readiness endpoint executes `SELECT 1` through SQLAlchemy so it reports whether the configured database can answer a query.

The backend reads settings from environment variables and the repository-root `.env` file. The example file contains local development defaults only. The database URL stays on the backend; the browser receives only the API base URL from its own Vite environment.

SQLAlchemy owns the initial `analyses` table mapping. Alembic owns schema changes, with revision `0001_create_analyses` creating the table and its downgrade removing that table. Downgrading this revision deletes all rows in `analyses`, so only use it on an empty or intentionally disposable foundation database. No capture, flow, event, or detection data is processed or stored yet. Future schema migrations must preserve data and be reviewed as part of the corresponding milestone.

For startup instructions and verification commands, see the repository [README](../../README.md).
