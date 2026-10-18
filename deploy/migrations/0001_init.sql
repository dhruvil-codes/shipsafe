-- Cloudflare D1 Migration for ShipSafe Production
-- Version: 0001_init.sql

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  environment TEXT NOT NULL,
  security_authorization TEXT,
  security_authorization_revision INTEGER DEFAULT 0,
  verification_token TEXT NOT NULL,
  verified_at TEXT,
  verification_expires_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_owners (
  project_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  PRIMARY KEY (project_id, owner),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_projects_url ON projects (url);
CREATE INDEX IF NOT EXISTS idx_project_owners_owner ON project_owners (owner);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  project_name TEXT,
  url TEXT NOT NULL,
  hostname TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('standard', 'deep', 'website', 'lab')),
  status TEXT NOT NULL CHECK (status IN ('QUEUED', 'CLAIMED', 'RUNNING', 'PROCESSING_RESULTS', 'COMPLETED', 'FAILED', 'RETRY_PENDING', 'CANCELLED', 'EXPIRED')),
  priority INTEGER NOT NULL DEFAULT 10,
  retry_count INTEGER NOT NULL DEFAULT 0,
  max_retries INTEGER NOT NULL DEFAULT 2,
  next_retry_at INTEGER DEFAULT 0,
  lease_worker_id TEXT,
  leased_at INTEGER,
  lease_expires_at INTEGER,
  score INTEGER,
  coverage INTEGER,
  report_key TEXT,
  report_manifest TEXT,
  error_code TEXT,
  error_message TEXT,
  scope_accepted INTEGER NOT NULL DEFAULT 1,
  authorization_id TEXT,
  user_ip TEXT,
  user_id TEXT,
  webhook_url TEXT,
  previous_score INTEGER,
  score_delta INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scans_status_priority ON scans (status, priority DESC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans (hostname, status);
CREATE INDEX IF NOT EXISTS idx_scans_lease_expires ON scans (lease_expires_at, status);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scan_events (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  message TEXT NOT NULL,
  check_id TEXT,
  status TEXT CHECK (status IN ('passed', 'observation', 'skipped')),
  timestamp INTEGER NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_scan ON scan_events (scan_id, timestamp ASC);

CREATE TABLE IF NOT EXISTS scan_findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  check_id TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  classification TEXT CHECK (classification IN ('hardening', 'vulnerability')),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence TEXT NOT NULL,
  remediation TEXT NOT NULL,
  cwe TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings (scan_id);

CREATE TABLE IF NOT EXISTS cached_reports (
  cache_key TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  hostname TEXT NOT NULL,
  mode TEXT NOT NULL,
  report_key TEXT NOT NULL,
  score INTEGER,
  coverage INTEGER,
  summary_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cached_reports_lookup ON cached_reports (cache_key, expires_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL,
  window_expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits (window_expires_at);

CREATE TABLE IF NOT EXISTS queue_metrics (
  id TEXT PRIMARY KEY,
  rolling_avg_duration REAL NOT NULL DEFAULT 15.0,
  updated_at INTEGER NOT NULL
);