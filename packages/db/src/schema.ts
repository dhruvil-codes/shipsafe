import {
  integer,
  pgTable,
  real,
  text,
  timestamp,
} from "drizzle-orm/pg-core";

/** Scan lifecycle states (PRD Section 14 subset used by orchestration). */
export const SCAN_STATUSES = [
  "QUEUED",
  "PROVISIONING",
  "RUNNING",
  "PROCESSING",
  "COMPLETED",
  "FAILED",
  "CANCELLED",
] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const projects = pgTable("projects", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  url: text("url").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
});

export const scans = pgTable("scans", {
  id: text("id").primaryKey(),
  projectId: text("project_id")
    .notNull()
    .references(() => projects.id),
  sandboxId: text("sandbox_id"),
  status: text("status").notNull().$type<ScanStatus>(),
  score: integer("score"),
  coverage: real("coverage"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
});

export const findings = pgTable("findings", {
  id: text("id").primaryKey(),
  scanId: text("scan_id")
    .notNull()
    .references(() => scans.id),
  severity: text("severity").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  /** JSON-stringified evidence payload. */
  evidence: text("evidence").notNull(),
  remediation: text("remediation").notNull(),
  cwe: text("cwe"),
});

export const scanEvents = pgTable("scan_events", {
  id: text("id").primaryKey(),
  scanId: text("scan_id")
    .notNull()
    .references(() => scans.id),
  stage: text("stage").notNull(),
  message: text("message").notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true })
    .defaultNow()
    .notNull(),
});

export type Project = typeof projects.$inferSelect;
export type NewProject = typeof projects.$inferInsert;
export type Scan = typeof scans.$inferSelect;
export type NewScan = typeof scans.$inferInsert;
export type Finding = typeof findings.$inferSelect;
export type NewFinding = typeof findings.$inferInsert;
export type ScanEvent = typeof scanEvents.$inferSelect;
export type NewScanEvent = typeof scanEvents.$inferInsert;
