export type Priority = "P0" | "P1" | "P2" | "P3";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export interface Component {
  id: string;
  name: string;
  version: string;
  purl: string | null;
  ecosystem: string | null;
  scope: string;
}
export interface Inventory {
  name: string;
  format: "CycloneDX" | "SPDX";
  components: Component[];
  edges: [string, string][];
  roots: string[];
  warnings: string[];
  inputHash: string;
}
export interface Advisory {
  id: string;
  aliases: string[];
  summary: string;
  details: string;
  modified: string;
  withdrawn: string | null;
  severity: Severity;
  cvss: number | null;
  affected: {
    purl: string | null;
    name: string;
    ecosystem: string;
    fixed: string[];
  }[];
  references: string[];
}
export type SourceStatus = "ok" | "error";
export interface QueryEvidence {
  purl: string;
  ids: string[];
  status: SourceStatus;
  error?: string;
}
export interface KevEntry {
  cveID: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
}
export interface EpssEntry {
  cve: string;
  epss: number;
  percentile: number;
  date: string;
}
export interface Snapshot {
  schema: "faultline.evidence/v1";
  mode: "live" | "demo";
  acquiredAt: string;
  queries: QueryEvidence[];
  advisories: Advisory[];
  kev: { status: SourceStatus; entries: KevEntry[]; error?: string };
  epss: { status: SourceStatus; entries: EpssEntry[]; error?: string };
  warnings: string[];
}
export interface Context {
  exposure: "internet" | "internal" | "unknown";
  criticality: "critical" | "standard";
}
export const DEFAULT_CONTEXT: Context = {
  exposure: "unknown",
  criticality: "standard",
};
export interface Finding {
  key: string;
  componentId: string;
  id: string;
  aliases: string[];
  advisoryIds: string[];
  summary: string;
  details: string;
  severity: Severity;
  cvss: number | null;
  priority: Priority;
  score: number;
  reasons: string[];
  kev: KevEntry | null;
  epss: EpssEntry | null;
  fixed: string[];
  path: string[];
  dependents: number;
  references: string[];
}
export interface Report {
  schema: "faultline.report/v1";
  generatedAt: string;
  inventory: Inventory;
  context: Context;
  evidence: {
    hash: string;
    acquiredAt: string;
    mode: Snapshot["mode"];
    kev: SourceStatus;
    epss: SourceStatus;
  };
  complete: boolean;
  coverage: {
    queried: number;
    queryable: number;
    total: number;
    skipped: number;
  };
  findings: Finding[];
  warnings: string[];
  plan: {
    componentId: string;
    priority: Priority;
    findingKeys: string[];
    score: number;
  }[];
}
