# SENTINEL

SENTINEL is a defensive network intrusion detection system. The current Day 1 foundation provides a FastAPI service, a React dashboard shell, and MySQL-backed persistence setup. Packet analysis and detection are not implemented yet.

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

The initial database contains only the `analyses` foundation table. Future schema changes must be made through Alembic migrations.
