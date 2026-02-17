# Sovereign

A lightweight full-stack starter:

- **Backend**: FastAPI + SQLite + JWT auth
- **Frontend**: React + Vite
- **Orchestration**: Docker Compose

## Project structure

```text
/sovereign
  /backend
  /frontend
  docker-compose.yml
```

## Run locally with Docker

```bash
cd sovereign
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend docs: http://localhost:8000/docs

## API endpoints

- `POST /register` — create user
- `POST /login` — get JWT token
- `GET /me` — retrieve current user using bearer token
- `GET /health` — service health check
