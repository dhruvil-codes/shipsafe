export interface D1PreparedStatement {
  bind(...values: any[]): D1PreparedStatement;
  first<T = unknown>(colName?: string): Promise<T | null>;
  run<T = unknown>(): Promise<{ success: boolean; meta: { changes: number } }>;
  all<T = unknown>(): Promise<{ results: T[] }>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<any[]>;
  exec(query: string): Promise<any>;
}

export interface R2Object {
  text(): Promise<string>;
  json<T = unknown>(): Promise<T>;
}

export interface R2Bucket {
  get(key: string): Promise<R2Object | null>;
  put(key: string, value: any, options?: any): Promise<any>;
  delete(key: string): Promise<void>;
}

export interface ExecutionContext {
  waitUntil(promise: Promise<any>): void;
  passThroughOnException(): void;
}

export interface ScheduledEvent {
  cron: string;
  type: string;
  scheduledTime: number;
}

export interface Env {
  DB: D1Database;
  REPORTS_BUCKET?: R2Bucket;
  ENVIRONMENT?: string;
  VM_WORKER_SECRET?: string;
  TURNSTILE_SECRET_KEY?: string;
  RATE_LIMIT_PER_IP_MINUTE?: string;
  RATE_LIMIT_PER_TARGET_MINUTE?: string;
  MAX_QUEUE_DEPTH?: string;
  CACHE_TTL_SECONDS?: string;
  ENABLE_TURNSTILE?: string;
}

export interface ScanJob {
  id: string;
  projectId: string;
  projectName?: string;
  url: string;
  hostname: string;
  mode: "standard" | "deep" | "website" | "lab";
  status:
    | "QUEUED"
    | "CLAIMED"
    | "RUNNING"
    | "PROCESSING_RESULTS"
    | "COMPLETED"
    | "FAILED"
    | "RETRY_PENDING"
    | "CANCELLED"
    | "EXPIRED";
  priority: number;
  retryCount: number;
  maxRetries: number;
  nextRetryAt?: number;
  leaseWorkerId?: string;
  leasedAt?: number;
  leaseExpiresAt?: number;
  score?: number;
  coverage?: number;
  reportKey?: string;
  reportManifest?: Record<string, unknown>;
  errorCode?: string;
  errorMessage?: string;
  scopeAccepted: boolean;
  authorizationId?: string;
  userIp?: string;
  userId?: string;
  createdAt: number;
  updatedAt: number;
  completedAt?: number;
}

export interface ScanEvent {
  id: string;
  scanId: string;
  stage: string;
  message: string;
  checkId?: string;
  status?: "passed" | "observation" | "skipped";
  timestamp: number;
}

export interface ScanFinding {
  id: string;
  scanId: string;
  checkId?: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  classification?: "hardening" | "vulnerability";
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  createdAt: number;
}

export interface QueueMetrics {
  queuedCount: number;
  runningCount: number;
  completedCount: number;
  failedCount: number;
  avgWaitTimeSec: number;
  cacheHitPercentage: number;
  workerUtilizationPercent: number;
}
