import type {
  Advisory,
  Context,
  Finding,
  Inventory,
  Priority,
  Report,
  Severity,
  Snapshot,
} from "./model.js";
import { DEFAULT_CONTEXT } from "./model.js";
import { aliasGroups, DependencyGraph } from "./graph.js";
import { digest, InputError } from "./validation.js";
import { parsePurl } from "./input.js";
const rank: Record<Severity, number> = {
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};
export function validateContext(value: unknown): Context {
  if (value === undefined) return { ...DEFAULT_CONTEXT };
  if (!value || typeof value !== "object")
    throw new InputError("Invalid context.");
  const c = value as Record<string, unknown>;
  if (
    !["internet", "internal", "unknown"].includes(String(c.exposure)) ||
    !["critical", "standard"].includes(String(c.criticality))
  )
    throw new InputError("Choose a valid exposure and criticality.");
  return {
    exposure: c.exposure as Context["exposure"],
    criticality: c.criticality as Context["criticality"],
  };
}
function affectedMatches(
  a: Advisory["affected"][number],
  purl: string,
): boolean {
  const p = parsePurl(purl)!;
  if (a.name === p.name && a.ecosystem === p.ecosystem) return true;
  if (a.purl) {
    // OSV affected package URLs are typically unversioned; strip only the version suffix.
    const clean = (s: string): string =>
      s.split(/[?#]/)[0]!.replace(/@[^/@]+$/, "");
    return clean(a.purl) === clean(purl);
  }
  return false;
}
export function analyze(
  inventory: Inventory,
  snapshot: Snapshot,
  context: Context = DEFAULT_CONTEXT,
  now = new Date().toISOString(),
): Report {
  const graph = new DependencyGraph(inventory),
    warnings = [...inventory.warnings, ...snapshot.warnings];
  const qmap = new Map(snapshot.queries.map((q) => [q.purl, q])),
    amap = new Map(snapshot.advisories.map((a) => [a.id, a]));
  const kmap = new Map(snapshot.kev.entries.map((k) => [k.cveID, k])),
    emap = new Map(snapshot.epss.entries.map((e) => [e.cve, e]));
  let complete = snapshot.kev.status === "ok" && snapshot.epss.status === "ok";
  if (snapshot.mode === "demo")
    warnings.push(
      "DEMONSTRATION: curated historical advisories with illustrative EPSS values. Not current threat intelligence.",
    );
  if (snapshot.kev.status !== "ok")
    warnings.push(
      `KEV enrichment unavailable: ${snapshot.kev.error ?? "unknown error"}. Absence of a flag is inconclusive.`,
    );
  if (snapshot.epss.status !== "ok")
    warnings.push(
      `EPSS enrichment unavailable: ${snapshot.epss.error ?? "unknown error"}. Missing probabilities are unknown.`,
    );
  const age = Date.parse(now) - Date.parse(snapshot.acquiredAt);
  if (age > 48 * 3600000) {
    warnings.push(
      "Evidence snapshot is older than 48 hours; refresh before making a release decision.",
    );
    complete = false;
  }
  if (age < -5 * 60000) {
    warnings.push("Evidence snapshot is future-dated. Check the source clock.");
    complete = false;
  }
  const findings: Finding[] = [];
  let queried = 0;
  for (const component of inventory.components) {
    if (!component.purl) continue;
    const q = qmap.get(component.purl);
    if (!q || q.status !== "ok") {
      complete = false;
      warnings.push(
        `${component.name}@${component.version}: ${q?.error ?? "no matching package query in evidence snapshot"}`,
      );
    } else queried++;
    const records: Advisory[] = [];
    for (const id of q?.ids ?? []) {
      const a = amap.get(id);
      if (!a) {
        complete = false;
        warnings.push(`Missing advisory detail for ${id}.`);
      } else if (!a.withdrawn) records.push(a);
    }
    for (const group of aliasGroups(records)) {
      const aliases = [
        ...new Set(group.flatMap((a) => [a.id, ...a.aliases])),
      ].sort();
      const id = aliases.find((a) => /^CVE-/.test(a)) ?? aliases[0]!;
      const best = [...group].sort(
        (a, b) =>
          rank[b.severity] - rank[a.severity] ||
          (b.cvss ?? 0) - (a.cvss ?? 0) ||
          a.id.localeCompare(b.id),
      )[0]!;
      const kev =
        snapshot.kev.status === "ok"
          ? (aliases.map((a) => kmap.get(a)).find(Boolean) ?? null)
          : null;
      const epss =
        snapshot.epss.status === "ok"
          ? (aliases
              .flatMap((a) => (emap.get(a) ? [emap.get(a)!] : []))
              .sort((a, b) => b.epss - a.epss)[0] ?? null)
          : null;
      if (epss && Date.parse(now) - Date.parse(epss.date) > 72 * 3600000) {
        complete = false;
        warnings.push(`EPSS data for ${id} is older than 72 hours.`);
      }
      const reasons: string[] = [];
      let priority: Priority;
      if (kev) {
        priority = "P0";
        reasons.push(
          `Known exploitation: CISA KEV entry added ${kev.dateAdded}.`,
        );
      } else if ((epss?.epss ?? 0) >= 0.1) {
        priority = "P1";
        reasons.push(
          `EPSS ${(epss!.epss * 100).toFixed(2)}% exceeds the 10% triage threshold.`,
        );
      } else if (best.severity === "CRITICAL") {
        priority = "P1";
        reasons.push("Critical advisory severity warrants expedited review.");
      } else if (
        best.severity === "HIGH" &&
        (context.exposure === "internet" || context.criticality === "critical")
      ) {
        priority = "P1";
        reasons.push(
          "High severity combined with analyst-declared exposure or criticality.",
        );
      } else if (best.severity === "HIGH" || best.severity === "UNKNOWN") {
        priority = "P2";
        reasons.push(
          best.severity === "UNKNOWN"
            ? "Severity unknown; manual triage required."
            : "High severity; schedule a prioritized review.",
        );
      } else {
        priority = "P3";
        reasons.push(
          "Lower severity without a higher-priority exploitation signal in available evidence.",
        );
      }
      if (!epss)
        reasons.push(
          "EPSS unavailable for this finding; this does not mean zero exploitation probability.",
        );
      if (!kev)
        reasons.push(
          snapshot.kev.status === "ok"
            ? "No matching KEV entry in this snapshot; this does not prove safety."
            : "KEV status unknown because enrichment failed.",
        );
      const path = graph.pathTo(component.id);
      reasons.push(
        path.length
          ? `Declared dependency path: ${path.length - 1} hop${path.length === 2 ? "" : "s"}. This is not code reachability evidence.`
          : "No declared path from an application root. Code reachability is unknown.",
      );
      // A sorting heuristic, explicitly separate from probability and CVSS.
      const score = Math.round(
        (kev ? 60 : 0) +
          (epss?.epss ?? 0) * 20 +
          (best.cvss !== null ? best.cvss * 1.5 : rank[best.severity] * 3.75) +
          (context.exposure === "internet" ? 3 : 0) +
          (context.criticality === "critical" ? 2 : 0),
      );
      const fixed = [
        ...new Set(
          group.flatMap((a) =>
            a.affected
              .filter((p) => affectedMatches(p, component.purl!))
              .flatMap((p) => p.fixed),
          ),
        ),
      ].sort();
      findings.push({
        key: digest([component.purl, id, component.id]).slice(0, 24),
        componentId: component.id,
        id,
        aliases,
        advisoryIds: group.map((a) => a.id).sort(),
        summary: best.summary,
        details: best.details,
        severity: best.severity,
        cvss: best.cvss,
        priority,
        score,
        reasons,
        kev,
        epss,
        fixed,
        path,
        dependents: graph.dependents(component.id).size,
        references: [...new Set(group.flatMap((a) => a.references))],
      });
    }
  }
  const queryable = inventory.components.filter((c) => c.purl).length;
  if (!queryable) complete = false;
  findings.sort(
    (a, b) =>
      a.priority.localeCompare(b.priority) ||
      b.score - a.score ||
      a.key.localeCompare(b.key),
  );
  const tasks = new Map<string, Report["plan"][number]>();
  for (const f of findings) {
    const task = tasks.get(f.componentId) ?? {
      componentId: f.componentId,
      priority: f.priority,
      findingKeys: [],
      score: 0,
    };
    task.findingKeys.push(f.key);
    task.score += f.score;
    tasks.set(f.componentId, task);
  }
  const plan = [...tasks.values()].sort(
    (a, b) =>
      a.priority.localeCompare(b.priority) ||
      b.score - a.score ||
      a.componentId.localeCompare(b.componentId),
  );
  return {
    schema: "faultline.report/v1",
    generatedAt: now,
    inventory,
    context,
    evidence: {
      hash: digest(snapshot),
      acquiredAt: snapshot.acquiredAt,
      mode: snapshot.mode,
      kev: snapshot.kev.status,
      epss: snapshot.epss.status,
    },
    complete,
    coverage: {
      queried,
      queryable,
      total: inventory.components.length,
      skipped: inventory.components.length - queryable,
    },
    findings,
    warnings: [...new Set(warnings)],
    plan,
  };
}
/** A baseline is compared by versionless package identity and advisory aliases, not display order. */
export function compareReports(
  before: Report,
  after: Report,
): { added: string[]; persisting: string[]; noLongerObserved: string[] } {
  const identities = (r: Report): Map<string, Set<string>> => {
    const components = new Map(r.inventory.components.map((c) => [c.id, c]));
    const map = new Map<string, Set<string>>();
    for (const f of r.findings) {
      const c = components.get(f.componentId),
        identity =
          c?.purl?.replace(/@[^/@]+$/, "") ?? `${c?.ecosystem}:${c?.name}`;
      for (const alias of f.aliases) {
        const key = `${identity}|${alias}`;
        map.set(key, new Set([...(map.get(key) ?? []), f.key]));
      }
    }
    return map;
  };
  const a = identities(before),
    b = identities(after);
  const existing = new Set<string>(),
    observed = new Set<string>();
  for (const [identity, keys] of b)
    if (a.has(identity)) {
      for (const k of keys) existing.add(k);
      for (const k of a.get(identity)!) observed.add(k);
    }
  return {
    added: after.findings.filter((f) => !existing.has(f.key)).map((f) => f.key),
    persisting: [...existing],
    noLongerObserved: before.findings
      .filter((f) => !observed.has(f.key))
      .map((f) => f.key),
  };
}
