import type {
  Advisory,
  EpssEntry,
  Inventory,
  KevEntry,
  QueryEvidence,
  Severity,
  Snapshot,
} from "./model.js";
import {
  arr,
  date,
  InputError,
  obj,
  required,
  safeURL,
  str,
} from "./validation.js";
import { parsePurl } from "./input.js";
import { cvss3 } from "./cvss.js";
const SEVERITIES: Severity[] = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export function normalizeAdvisory(value: unknown): Advisory {
  const r = obj(value, "OSV record");
  let score: number | null = null;
  for (const raw of arr(r.severity)) {
    const s = obj(raw);
    const n = cvss3(str(s.score));
    if (n !== null) score = Math.max(score ?? 0, n);
  }
  const db = r.database_specific ? obj(r.database_specific) : {};
  let severity: Severity = SEVERITIES.includes(
    str(db.severity).toUpperCase() as Severity,
  )
    ? (str(db.severity).toUpperCase() as Severity)
    : "UNKNOWN";
  const affected = arr(r.affected).map((raw) => {
    const a = obj(raw),
      p = a.package ? obj(a.package) : {};
    const es = a.ecosystem_specific ? obj(a.ecosystem_specific) : {};
    const s = str(es.severity).toUpperCase() as Severity;
    if (SEVERITIES.indexOf(s) > SEVERITIES.indexOf(severity)) severity = s;
    const fixed: string[] = [];
    for (const range of arr(a.ranges)) {
      const rangeObj = obj(range);
      if (rangeObj.type === "GIT") continue;
      for (const event of arr(rangeObj.events)) {
        const e = obj(event);
        if (typeof e.fixed === "string") fixed.push(str(e.fixed));
      }
    }
    return {
      purl: typeof p.purl === "string" ? p.purl : null,
      name: str(p.name),
      ecosystem: str(p.ecosystem),
      fixed: [...new Set(fixed)].sort(),
    };
  });
  if (score !== null)
    severity =
      score >= 9
        ? "CRITICAL"
        : score >= 7
          ? "HIGH"
          : score >= 4
            ? "MEDIUM"
            : "LOW";
  return {
    id: required(r.id, "advisory.id"),
    aliases: arr(r.aliases).map((a) => required(a, "alias")),
    summary: str(r.summary, str(r.id), 10000),
    details: str(r.details, "", 200000),
    modified: str(r.modified),
    withdrawn: typeof r.withdrawn === "string" ? r.withdrawn : null,
    severity,
    cvss: score,
    affected,
    references: arr(r.references)
      .map((r) => safeURL(obj(r).url))
      .filter((s): s is string => s !== null)
      .slice(0, 30),
  };
}
export function normalizeKev(value: unknown): KevEntry[] {
  const data = obj(value, "CISA catalog");
  if (!Array.isArray(data.vulnerabilities))
    throw new InputError("CISA catalog has no vulnerabilities array.");
  return arr(data.vulnerabilities, "KEV entries", 20000).map((raw) => {
    const r = obj(raw),
      cveID = required(r.cveID, "cveID");
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveID))
      throw new InputError("Invalid CVE in KEV response.");
    return {
      cveID,
      dateAdded: str(r.dateAdded),
      dueDate: str(r.dueDate),
      requiredAction: str(r.requiredAction, "", 10000),
    };
  });
}
export function normalizeEpss(value: unknown): EpssEntry[] {
  const data = obj(value);
  if (!Array.isArray(data.data) || data.status !== "OK")
    throw new InputError("Invalid EPSS response.");
  return arr(data.data).map((raw) => {
    const r = obj(raw),
      cve = required(r.cve, "EPSS CVE"),
      epss = r.epss === null || r.epss === "" ? NaN : Number(r.epss),
      percentile =
        r.percentile === null || r.percentile === ""
          ? NaN
          : Number(r.percentile);
    if (
      !/^CVE-\d{4}-\d{4,}$/.test(cve) ||
      !Number.isFinite(epss) ||
      !Number.isFinite(percentile) ||
      epss < 0 ||
      epss > 1 ||
      percentile < 0 ||
      percentile > 1
    )
      throw new InputError("Invalid EPSS probability.");
    return { cve, epss, percentile, date: date(r.date, "EPSS date") };
  });
}
export function validateSnapshot(value: unknown): Snapshot {
  const r = obj(value, "evidence");
  if (
    r.schema !== "faultline.evidence/v1" ||
    !["demo", "live"].includes(str(r.mode))
  )
    throw new InputError("Unsupported evidence snapshot.");
  date(r.acquiredAt, "acquiredAt");
  const queries = arr(r.queries, "queries", 1500).map((raw) => {
    const q = obj(raw);
    required(q.purl, "query.purl");
    if (!["ok", "error"].includes(str(q.status)))
      throw new InputError("Invalid query status.");
    return {
      purl: str(q.purl),
      ids: arr(q.ids, "ids", 2000).map((i) => required(i, "advisory ID")),
      status: q.status as "ok" | "error",
      ...(q.error ? { error: str(q.error) } : {}),
    };
  });
  if (new Set(queries.map((q) => q.purl)).size !== queries.length)
    throw new InputError("Duplicate evidence queries.");
  // Snapshot advisories use normalized shape. Validate all fields before accepting them.
  const advisories = arr(r.advisories, "advisories", 2000).map((raw) => {
    const a = obj(raw);
    const cvss = a.cvss === null ? null : Number(a.cvss);
    if (
      (cvss !== null && (!Number.isFinite(cvss) || cvss < 0 || cvss > 10)) ||
      !SEVERITIES.includes(str(a.severity) as Severity)
    )
      throw new InputError("Invalid advisory severity.");
    return {
      id: required(a.id, "advisory.id"),
      aliases: arr(a.aliases).map((x) => required(x, "alias")),
      summary: str(a.summary, "", 10000),
      details: str(a.details, "", 200000),
      modified: str(a.modified),
      withdrawn: a.withdrawn === null ? null : str(a.withdrawn),
      severity: a.severity as Severity,
      cvss,
      affected: arr(a.affected).map((raw) => {
        const p = obj(raw);
        return {
          purl: p.purl === null ? null : str(p.purl),
          name: str(p.name),
          ecosystem: str(p.ecosystem),
          fixed: arr(p.fixed).map((x) => str(x)),
        };
      }),
      references: arr(a.references)
        .map(safeURL)
        .filter((s): s is string => s !== null),
    };
  });
  if (new Set(advisories.map((a) => a.id)).size !== advisories.length)
    throw new InputError("Duplicate advisory records.");
  const kev = obj(r.kev),
    epss = obj(r.epss);
  if (![kev.status, epss.status].every((s) => s === "ok" || s === "error"))
    throw new InputError("Invalid enrichment status.");
  const kevEntries = normalizeKev({
    vulnerabilities: arr(kev.entries, "KEV", 20000),
  });
  const epssEntries = normalizeEpss({ status: "OK", data: arr(epss.entries) });
  return {
    schema: "faultline.evidence/v1",
    mode: r.mode as Snapshot["mode"],
    acquiredAt: str(r.acquiredAt),
    queries,
    advisories,
    kev: {
      status: kev.status as "ok" | "error",
      entries: kevEntries,
      ...(kev.error ? { error: str(kev.error) } : {}),
    },
    epss: {
      status: epss.status as "ok" | "error",
      entries: epssEntries,
      ...(epss.error ? { error: str(epss.error) } : {}),
    },
    warnings: arr(r.warnings).map((x) => str(x)),
  };
}
export type Fetcher = typeof fetch;
const HOSTS = new Set(["api.osv.dev", "api.first.org", "www.cisa.gov"]);
export async function fetchJSON(
  url: string,
  init: RequestInit = {},
  fetcher: Fetcher = fetch,
): Promise<unknown> {
  const parsed = new URL(url);
  if (
    parsed.protocol !== "https:" ||
    !HOSTS.has(parsed.hostname) ||
    parsed.username ||
    parsed.password ||
    parsed.port
  )
    throw new InputError("Unapproved intelligence endpoint.");
  for (let attempt = 0; attempt < 3; attempt++) {
    const response = await fetcher(url, {
      ...init,
      redirect: "error",
      signal: AbortSignal.any([
        AbortSignal.timeout(20000),
        ...(init.signal ? [init.signal] : []),
      ]),
      headers: {
        "User-Agent": "Faultline/1.0 (dependency-triage)",
        Accept: "application/json",
        ...init.headers,
      },
    });
    if ((response.status === 429 || response.status >= 500) && attempt < 2) {
      await new Promise((r) => setTimeout(r, 250 * 2 ** attempt));
      continue;
    }
    if (!response.ok)
      throw new Error(
        `Intelligence provider returned HTTP ${response.status}.`,
      );
    if (!response.body) throw new Error("Empty intelligence response.");
    const chunks: Uint8Array[] = [];
    let length = 0;
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > 16 * 1024 * 1024)
          throw new Error("Intelligence response exceeds 16 MiB.");
        chunks.push(value);
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  }
  throw new Error("Provider retries exhausted.");
}
export async function pool<T, R>(
  items: T[],
  concurrency: number,
  work: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, async () => {
      while (next < items.length) {
        const index = next++;
        results[index] = await work(items[index]!, index);
      }
    }),
  );
  return results;
}
const errorText = (e: unknown): string =>
  e instanceof Error ? e.message.slice(0, 500) : "Provider request failed.";
export async function collectEvidence(
  inventory: Inventory,
  fetcher: Fetcher = fetch,
): Promise<Snapshot> {
  const budget = AbortSignal.timeout(180000);
  const boundedFetcher: Fetcher = (input, init) =>
    fetcher(input, {
      ...init,
      signal: AbortSignal.any([budget, ...(init?.signal ? [init.signal] : [])]),
    });
  const purls = [
    ...new Set(inventory.components.flatMap((c) => (c.purl ? [c.purl] : []))),
  ].sort();
  const queries: QueryEvidence[] = [],
    warnings: string[] = [];
  const advisoryMap = new Map<string, Advisory>();
  // Small batches bound request size and honor OSV's per-query pagination tokens.
  for (let offset = 0; offset < purls.length; offset += 100) {
    const batch = purls.slice(offset, offset + 100);
    let pending = batch.map((purl) => ({
      purl,
      ids: new Set<string>(),
      token: "",
    }));
    const accumulated = [...pending];
    try {
      for (let page = 0; pending.length; page++) {
        if (page >= 20)
          throw new Error(
            "OSV pagination limit reached; results are incomplete.",
          );
        const payload = {
          queries: pending.map((q) => {
            const p = parsePurl(q.purl)!;
            return {
              package: { ecosystem: p.ecosystem, name: p.name },
              version: p.version,
              ...(q.token ? { page_token: q.token } : {}),
            };
          }),
        };
        const data = obj(
          await fetchJSON(
            "https://api.osv.dev/v1/querybatch",
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payload),
            },
            boundedFetcher,
          ),
        );
        const results = arr(data.results);
        if (results.length !== pending.length)
          throw new Error("OSV batch result count mismatch.");
        const following: typeof pending = [];
        results.forEach((raw, i) => {
          const result = obj(raw),
            q = pending[i]!;
          for (const v of arr(result.vulns))
            q.ids.add(required(obj(v).id, "OSV ID"));
          const token = str(result.next_page_token);
          if (token) {
            if (token === q.token)
              throw new Error("OSV repeated a pagination token.");
            q.token = token;
            following.push(q);
          }
        });
        pending = following;
      }
      for (const q of accumulated)
        queries.push({ purl: q.purl, ids: [...q.ids].sort(), status: "ok" });
    } catch (e) {
      for (const q of accumulated)
        queries.push({
          purl: q.purl,
          ids: [...q.ids].sort(),
          status: "error",
          error: errorText(e),
        });
    }
  }
  const ids = [...new Set(queries.flatMap((q) => q.ids))];
  if (ids.length > 2000) {
    for (const q of queries) {
      q.status = "error";
      q.error = "Advisory limit exceeded (2,000); narrow the inventory.";
    }
    warnings.push("Advisory detail retrieval capped at 2,000.");
  }
  await pool(ids.slice(0, 2000), 6, async (id) => {
    try {
      const a = normalizeAdvisory(
        await fetchJSON(
          `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,
          {},
          boundedFetcher,
        ),
      );
      if (a.id !== id) throw new Error("OSV advisory ID mismatch.");
      advisoryMap.set(id, a);
    } catch (e) {
      warnings.push(`Could not retrieve ${id}: ${errorText(e)}`);
    }
  });
  const cves = [
    ...new Set(
      [...advisoryMap.values()]
        .flatMap((a) => [a.id, ...a.aliases])
        .filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id)),
    ),
  ].sort();
  let kev: Snapshot["kev"], epss: Snapshot["epss"];
  const enrichment = await Promise.allSettled([
    fetchJSON(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      {},
      boundedFetcher,
    ).then(normalizeKev),
    (async () => {
      const entries: EpssEntry[] = [];
      for (let i = 0; i < cves.length; i += 50) {
        const raw = await fetchJSON(
          `https://api.first.org/data/v1/epss?cve=${cves.slice(i, i + 50).join(",")}&limit=100`,
          {},
          boundedFetcher,
        );
        const data = obj(raw);
        if (Number(data.total) > 100)
          throw new Error("Unexpected EPSS pagination.");
        entries.push(...normalizeEpss(raw));
      }
      return entries;
    })(),
  ]);
  kev =
    enrichment[0].status === "fulfilled"
      ? { status: "ok", entries: enrichment[0].value }
      : {
          status: "error",
          entries: [],
          error: errorText(enrichment[0].reason),
        };
  epss =
    enrichment[1].status === "fulfilled"
      ? { status: "ok", entries: enrichment[1].value }
      : {
          status: "error",
          entries: [],
          error: errorText(enrichment[1].reason),
        };
  return {
    schema: "faultline.evidence/v1",
    mode: "live",
    acquiredAt: new Date().toISOString(),
    queries,
    advisories: [...advisoryMap.values()].sort((a, b) =>
      a.id.localeCompare(b.id),
    ),
    kev,
    epss,
    warnings,
  };
}
