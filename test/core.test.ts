import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { parseInventory, parsePurl } from "../src/core/input.js";
import { aliasGroups, DependencyGraph } from "../src/core/graph.js";
import {
  analyze,
  compareReports,
  validateContext,
} from "../src/core/analyze.js";
import {
  collectEvidence,
  fetchJSON,
  normalizeAdvisory,
  normalizeEpss,
  validateSnapshot,
} from "../src/core/evidence.js";
import { canonical, digest, safeURL } from "../src/core/validation.js";
import { gate, markdown, sarif } from "../src/core/reports.js";
import { cvss3 } from "../src/core/cvss.js";
import type {
  Snapshot,
  Inventory,
  Advisory,
  Report,
} from "../src/core/model.js";
const cdxText = await readFile("examples/harbor.cdx.json", "utf8");
const inventory = parseInventory(cdxText);
const fixture = validateSnapshot(
  JSON.parse(await readFile("examples/demo-evidence.json", "utf8")) as unknown,
);
const NOW = "2025-01-15T12:00:00Z";
const clone = <T>(value: T): T => structuredClone(value);
function liveFixture(): Snapshot {
  const s = clone(fixture);
  s.mode = "live";
  return s;
}
test("CycloneDX and SPDX produce equivalent package and edge counts", async () => {
  const spdx = parseInventory(
    await readFile("examples/harbor.spdx.json", "utf8"),
  );
  assert.equal(inventory.components.length, 18);
  assert.equal(spdx.components.length, 18);
  assert.equal(spdx.edges.length, inventory.edges.length);
  assert.equal(spdx.roots.length, 1);
  assert.deepEqual(
    spdx.components.map((c) => c.purl).sort(),
    inventory.components.map((c) => c.purl).sort(),
  );
});
test("unsupported formats, duplicate references, and inconsistent versions are rejected", () => {
  assert.throws(() => parseInventory("{broken"), /Invalid JSON/);
  assert.throws(() => parseInventory("{}"), /CycloneDX/);
  const data = JSON.parse(cdxText);
  data.components.push(data.components[0]);
  assert.throws(() => parseInventory(JSON.stringify(data)), /Duplicate/);
  const other = JSON.parse(cdxText);
  other.components[0].version = "999";
  assert.throws(() => parseInventory(JSON.stringify(other)), /disagrees/);
});
test("missing edges remain unknown and dangling graph references are disclosed", () => {
  const data = JSON.parse(cdxText);
  data.dependencies = [{ ref: "harbor-gateway", dependsOn: ["absent"] }];
  const inv = parseInventory(JSON.stringify(data));
  assert.equal(inv.edges.length, 0);
  assert.ok(inv.warnings.some((w) => w.includes("unknown")));
  assert.ok(inv.warnings.some((w) => w.includes("omitted")));
});
test("Package URL parsing handles scopes, percent encoding, Maven names, PyPI normalization and coverage gaps", () => {
  assert.equal(parsePurl("pkg:npm/%40scope/name@1.2.3")?.name, "@scope/name");
  assert.equal(
    parsePurl(
      "pkg:maven/org.apache/log4j@2.0?repository_url=https://example.com",
    )?.name,
    "org.apache:log4j",
  );
  assert.equal(
    parsePurl("pkg:pypi/My_Package.Name@1.2")?.name,
    "my-package-name",
  );
  assert.equal(parsePurl("pkg:deb/debian/openssl@3.0"), null);
  assert.equal(parsePurl("pkg:npm/name"), null);
  assert.throws(() => parsePurl("pkg:npm/%XY@1"), /percent encoding/);
});
test("graph traversal terminates on cycles, preserves shortest paths, excludes self from dependents", () => {
  const inv: Inventory = {
    ...inventory,
    components: inventory.components
      .slice(0, 3)
      .map((c, i) => ({ ...c, id: ["a", "b", "c"][i]! })),
    roots: ["a"],
    edges: [
      ["a", "b"],
      ["b", "c"],
      ["c", "a"],
    ],
  };
  const g = new DependencyGraph(inv);
  assert.deepEqual(g.pathTo("c"), ["a", "b", "c"]);
  assert.deepEqual([...g.dependents("a")].sort(), ["b", "c"]);
  assert.deepEqual(g.pathTo("unseen"), []);
});
test("union-find merges transitive aliases but never unrelated advisories", () => {
  const groups = aliasGroups([
    { id: "A", aliases: ["CVE-X"] },
    { id: "B", aliases: ["A"] },
    { id: "C", aliases: ["CVE-Y"] },
  ]);
  assert.deepEqual(
    groups.map((g) => g.map((a) => a.id).sort()),
    [["A", "B"], ["C"]],
  );
});
test("CVSS 3.x base scores match published reference vectors, including scope changed and zero impact", () => {
  assert.equal(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10);
  assert.equal(cvss3("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"), 7.5);
  assert.equal(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
  assert.equal(cvss3("CVSS:4.0/AV:N"), null);
  assert.equal(cvss3("CVSS:3.1/AV:N/AV:L"), null);
});
test("OSV normalization extracts only non-GIT fixed endpoints and safe references", () => {
  const a = normalizeAdvisory({
    id: "A",
    severity: [
      {
        type: "CVSS_V3",
        score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
    ],
    affected: [
      {
        package: { name: "x", ecosystem: "npm" },
        ranges: [
          { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2" }] },
          { type: "GIT", events: [{ fixed: "deadbeef" }] },
        ],
      },
    ],
    references: [
      { url: "javascript:alert(1)" },
      { url: "https://example.org/advisory" },
    ],
  });
  assert.equal(a.cvss, 9.8);
  assert.equal(a.severity, "CRITICAL");
  assert.deepEqual(a.affected[0]?.fixed, ["1.2"]);
  assert.equal(a.references.length, 1);
});
test("demo produces traceable P0 findings, deterministic evidence hashes, and no gating pass", () => {
  const report = analyze(inventory, fixture, undefined, NOW);
  assert.equal(report.findings.length, 6);
  assert.equal(report.findings.filter((f) => f.priority === "P0").length, 3);
  assert.equal(report.coverage.queried, 17);
  assert.equal(report.coverage.skipped, 1);
  assert.deepEqual(
    report.findings.find((f) => f.id === "CVE-2022-1471")?.path,
    ["harbor-gateway", "jackson-dataformat-yaml", "snakeyaml"],
  );
  assert.equal(report.evidence.hash, digest(fixture));
  assert.equal(gate(report, "none").code, 2);
  assert.equal(canonical({ b: 1, a: 2 }), canonical({ a: 2, b: 1 }));
});
test("aliases merge per component, withdrawn advisories are excluded, records remain auditable", () => {
  const s = liveFixture(),
    original = s.advisories[0]!;
  s.advisories.push({
    ...clone(original),
    id: "GHSA-alias",
    aliases: [original.id],
  });
  s.queries.find((q) => q.ids.includes(original.id))!.ids.push("GHSA-alias");
  let r = analyze(inventory, s, undefined, NOW);
  assert.equal(r.findings.length, 6);
  assert.equal(
    r.findings.find((f) => f.id === original.id)?.advisoryIds.length,
    2,
  );
  s.advisories[0]!.withdrawn = NOW;
  s.advisories.at(-1)!.withdrawn = NOW;
  r = analyze(inventory, s, undefined, NOW);
  assert.equal(r.findings.length, 5);
});
test("missing query, missing detail, failed enrichment, stale and future evidence cannot pass a gate", () => {
  for (const mutate of [
    (s: Snapshot) => {
      s.queries.pop();
    },
    (s: Snapshot) => {
      s.advisories.pop();
    },
    (s: Snapshot) => {
      s.kev.status = "error";
    },
    (s: Snapshot) => {
      s.epss.status = "error";
    },
    (s: Snapshot) => {
      s.acquiredAt = "2024-01-01";
    },
    (s: Snapshot) => {
      s.acquiredAt = "2026-01-01";
    },
  ]) {
    const s = liveFixture();
    mutate(s);
    const r = analyze(inventory, s, undefined, NOW);
    assert.equal(r.complete, false);
    assert.equal(gate(r, "none").code, 2);
  }
});
test("a successful no-result query is distinguished from an unqueried package", () => {
  const s = liveFixture();
  s.queries.forEach((q) => (q.ids = []));
  const r = analyze(inventory, s, undefined, NOW);
  assert.equal(r.complete, true);
  assert.equal(r.findings.length, 0);
  assert.equal(gate(r, "P1").code, 0);
});
test("priority policy uses EPSS probability rather than percentile and honors context", () => {
  const s = liveFixture();
  s.kev.entries = [];
  const a = s.advisories.at(-1)!;
  a.severity = "HIGH";
  a.cvss = 7.5;
  s.epss.entries.find((e) => e.cve === a.id)!.epss = 0.099;
  let r = analyze(inventory, s, undefined, NOW);
  assert.equal(r.findings.find((f) => f.id === a.id)!.priority, "P2");
  r = analyze(
    inventory,
    s,
    { exposure: "internet", criticality: "standard" },
    NOW,
  );
  assert.equal(r.findings.find((f) => f.id === a.id)!.priority, "P1");
  s.epss.entries.find((e) => e.cve === a.id)!.epss = 0.1;
  r = analyze(inventory, s, undefined, NOW);
  assert.equal(r.findings.find((f) => f.id === a.id)!.priority, "P1");
});
test("fixed version candidates are restricted to the matching package", () => {
  const s = liveFixture();
  s.advisories[0]!.affected.push({
    purl: "pkg:npm/unrelated",
    name: "unrelated",
    ecosystem: "npm",
    fixed: ["9999"],
  });
  assert.ok(
    !analyze(inventory, s, undefined, NOW).findings.some((f) =>
      f.fixed.includes("9999"),
    ),
  );
});
test("baseline comparison survives version changes and advisory ID alias changes", () => {
  const before = analyze(inventory, liveFixture(), undefined, NOW),
    after = clone(before);
  after.inventory.components.forEach((c) => {
    c.version = "999";
    if (c.purl) c.purl = c.purl.replace(/@[^/@]+$/, "@999");
  });
  after.findings[0]!.id = "NEW-ID";
  after.findings[0]!.key = "newkey";
  const delta = compareReports(before, after);
  assert.equal(delta.added.length, 0);
  assert.equal(delta.noLongerObserved.length, 0);
  assert.ok(delta.persisting.includes("newkey"));
});
test("report exports preserve evidence and escape untrusted Markdown text", () => {
  const r = analyze(inventory, liveFixture(), undefined, NOW);
  r.inventory.name = "<script>|\n**x";
  const md = markdown(r);
  assert.ok(!md.includes("<script>"));
  assert.ok(md.includes(r.evidence.hash));
  const output = sarif(r) as {
    version: string;
    runs: { results: unknown[] }[];
  };
  assert.equal(output.version, "2.1.0");
  assert.equal(output.runs[0]!.results.length, 6);
  assert.equal(gate(r, "P0").code, 1);
  assert.throws(() =>
    validateContext({ exposure: "made-up", criticality: "standard" }),
  );
});
test("snapshot validation rejects malformed probabilities, duplicate queries and dangerous URLs", () => {
  assert.throws(() =>
    normalizeEpss({
      status: "OK",
      data: [
        { cve: "CVE-2021-44228", epss: -1, percentile: 1, date: "2025-01-15" },
      ],
    }),
  );
  const s = liveFixture();
  s.queries.push(s.queries[0]!);
  assert.throws(() => validateSnapshot(s), /Duplicate/);
  assert.throws(() =>
    normalizeEpss({
      status: "OK",
      data: [
        {
          cve: "CVE-2021-44228",
          epss: null,
          percentile: 1,
          date: "2025-01-15",
        },
      ],
    }),
  );
  assert.equal(safeURL("javascript:alert(1)"), null);
  assert.equal(safeURL("https://user:pass@example.org"), null);
});
test("provider endpoints are pinned and redirects forbidden", async () => {
  await assert.rejects(fetchJSON("https://attacker.invalid"), /Unapproved/);
  let redirect: RequestRedirect | undefined;
  const fake: typeof fetch = async (_input, init) => {
    redirect = init?.redirect;
    return Response.json({ ok: true });
  };
  await fetchJSON("https://api.osv.dev/v1/querybatch", {}, fake);
  assert.equal(redirect, "error");
});
test("OSV per-query pagination and detail lookup work; incomplete pagination fails closed", async () => {
  const inv = {
    ...inventory,
    components: inventory.components.filter((c) => c.id === "log4j-core"),
  };
  let pageCount = 0;
  const fake: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.includes("querybatch")) {
      pageCount++;
      const body = JSON.parse(String(init?.body));
      if (pageCount === 2) assert.equal(body.queries[0].page_token, "next");
      return Response.json({
        results: [
          {
            vulns: [{ id: pageCount === 1 ? "A" : "B" }],
            ...(pageCount === 1 ? { next_page_token: "next" } : {}),
          },
        ],
      });
    }
    if (url.includes("/vulns/"))
      return Response.json({
        id: url.endsWith("/A") ? "A" : "B",
        aliases: [],
        affected: [],
      });
    if (url.includes("cisa.gov")) return Response.json({ vulnerabilities: [] });
    return Response.json({ status: "OK", total: 0, data: [] });
  };
  const s = await collectEvidence(inv, fake);
  assert.equal(pageCount, 2);
  assert.deepEqual(s.queries[0]!.ids, ["A", "B"]);
  assert.equal(s.advisories.length, 2);
  assert.equal(s.queries[0]!.status, "ok");
  const broken: typeof fetch = async () => Response.json({ results: [] });
  const failed = await collectEvidence(inv, broken);
  assert.equal(failed.queries[0]!.status, "error");
  assert.equal(failed.kev.status, "error");
});
test("provider transient HTTP failures are retried within a fixed budget", async () => {
  let calls = 0;
  const fake: typeof fetch = async () =>
    ++calls < 3
      ? new Response("busy", { status: 503 })
      : Response.json({ ok: true });
  assert.deepEqual(
    await fetchJSON("https://api.osv.dev/v1/querybatch", {}, fake),
    { ok: true },
  );
  assert.equal(calls, 3);
});
