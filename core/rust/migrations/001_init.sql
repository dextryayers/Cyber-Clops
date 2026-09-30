-- Phase 0 schema, version 001.
-- One file per project. WAL mode for concurrent readers.
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  value TEXT NOT NULL,
  kind TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subdomains (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  subdomain TEXT NOT NULL,
  ip TEXT,
  source TEXT,
  resolved INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ports (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  state TEXT NOT NULL,
  service TEXT,
  version TEXT,
  banner TEXT,
  latency_ms INTEGER
);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  tool TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  tool TEXT NOT NULL,
  target TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT
);
