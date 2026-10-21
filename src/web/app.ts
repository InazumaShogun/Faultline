import type { Component, Finding, Report, Snapshot } from "../core/model.js";
interface ResponseBundle {
  report: Report;
  snapshot: Snapshot;
  exports: { markdown: string; sarif: unknown };
}
type View =
  | "overview"
  | "findings"
  | "plan"
  | "inventory"
  | "evidence"
  | "method";
let bundle: ResponseBundle,
  view: View = "overview",
  query = "",
  filter = "all",
  page = 0;
let selectedComponent: string | null = null;
const app = document.querySelector<HTMLDivElement>("#app")!;
const esc = (value: unknown): string =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
const icons: Record<string, string> = {
  overview:
    '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  findings: '<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5m0 3v.1"/>',
  plan: '<path d="M9 6h12M9 12h12M9 18h12M3 6h.1M3 12h.1M3 18h.1"/>',
  inventory: '<path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5m-18 5 9 5 9-5"/>',
  evidence: '<path d="M14 3H5v18h14V8l-5-5Zm0 0v5h5M8 12h8m-8 4h6"/>',
  method: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.1"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  arrow: '<path d="M5 12h14m-6-6 6 6-6 6"/>',
  download: '<path d="M12 3v12m-4-4 4 4 4-4M4 16v5h16v-5"/>',
  upload: '<path d="M12 16V3m-5 5 5-5 5 5M4 16v5h16v-5"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2 6M20 3v8h-8"/>',
};
const icon = (name: string, size = 17): string =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name] ?? icons.arrow}</svg>`;
const priority = (f: Pick<Finding, "priority">): string =>
  `<span class="priority ${f.priority}">${f.priority}<span>·</span>${{ P0: "Immediate", P1: "Expedite", P2: "Prioritize", P3: "Routine" }[f.priority]}</span>`;
const comp = (id: string): Component =>
  bundle.report.inventory.components.find((c) => c.id === id)!;
const counts = (): Record<string, number> =>
  Object.fromEntries(
    ["P0", "P1", "P2", "P3"].map((p) => [
      p,
      bundle.report.findings.filter((f) => f.priority === p).length,
    ]),
  );
function setView(next: View): void {
  view = next;
  page = 0;
  render();
  document.querySelector("#main")?.scrollIntoView({ block: "start" });
}
function render(): void {
  const r = bundle.report,
    n = counts(),
    name = r.inventory.name;
  const titles: Record<View, string> = {
    overview: "The exposure brief.",
    findings: "Follow the evidence.",
    plan: "A plan of repair.",
    inventory: "Know what you carry.",
    evidence: "Nothing on blind faith.",
    method: "Judgment, made visible.",
  };
  const subtitles: Record<View, string> = {
    overview: "Your dependencies. Their weak points. A clear place to start.",
    findings:
      "Every priority comes with a reason and a trail back to its source.",
    plan: "One component at a time. Review, upgrade, test, then rescan.",
    inventory:
      "The declared components and relationships in your software inventory.",
    evidence:
      "Source provenance, coverage, and the boundaries of this investigation.",
    method:
      "An inspectable triage policy. No opaque risk scores. No invented certainty.",
  };
  app.innerHTML = `<div class="shell">
    <aside class="rail"><div class="brand"><svg class="brandmark" viewBox="0 0 40 42" fill="none" aria-hidden="true"><path d="M8 36V6h28M8 20h19" stroke="#e4e9a5" stroke-width="2.5"/><path d="m25 1-7 18 11 4-7 18" stroke="#e98a65" stroke-width="2.5"/></svg><span class="brand-name">FAULTLINE</span></div><div class="brand-sub">DEPENDENCY INTELLIGENCE</div>
    <div class="eyebrow rail-section">INVESTIGATION</div><nav class="navigation" aria-label="Main navigation">${(
      [
        ["overview", "Overview", "01"],
        ["findings", "Findings", String(r.findings.length).padStart(2, "0")],
        ["plan", "Repair plan", "03"],
        ["inventory", "Inventory", "04"],
        ["evidence", "Evidence", "05"],
        ["method", "Method", "06"],
      ] as const
    )
      .map(
        ([key, label, number]) =>
          `<button class="nav ${view === key ? "active" : ""}" data-view="${key}" aria-label="${label}" ${view === key ? 'aria-current="page"' : ""}>${icon(key)}<span class="nav-text">${label}</span><span>${number}</span></button>`,
      )
      .join("")}</nav>
    <div class="rail-bottom"><div class="local-badge"><i class="dot"></i> LOCAL WORKSPACE</div><p class="rail-note">A clearer view of what<br>your software depends on.</p><div class="version"><span>FAULTLINE / 1.0</span><span>OPEN SOURCE ↗</span></div></div></aside>
    <div class="workspace"><header class="topbar"><div class="crumb">Workspace <span aria-hidden="true">/</span> <b>${esc(name)}</b></div><div class="topbar-right"><span class="session mono">EVIDENCE-LED / LOCAL-FIRST</span><button class="btn small" id="top-import">${icon("plus", 13)} New investigation</button><div class="avatar" title="Local analyst workspace">FL</div></div></header>
    <main class="main" id="main" tabindex="-1"><div class="page-heading"><div><div class="eyebrow issue-label">SUPPLY CHAIN / ${view === "overview" ? "EXPOSURE BRIEF" : view === "plan" ? "REPAIR PLAN" : view.toUpperCase()}</div><h1>${titles[view]}</h1><p>${subtitles[view]}</p></div><div class="heading-actions"><button class="btn" id="reload-demo">${icon("refresh", 13)} Reset demo</button><button class="btn dark" id="export">${icon("download", 14)} Export brief</button></div></div>
    ${r.evidence.mode === "demo" ? '<div class="demo-banner"><div><strong>DEMONSTRATION DATA</strong>A sample investigation. Historical advisories and illustrative signals, ready to explore.</div><button class="text-button" id="demo-import">Use your SBOM ↗</button></div>' : !r.complete ? '<div class="notice">Evidence is incomplete or stale. Review coverage and source failures before making a release decision.</div>' : ""}
    ${view === "overview" ? overview() : view === "findings" ? queue(true) : view === "plan" ? plan() : view === "inventory" ? inventory() : view === "evidence" ? evidence() : method()}
    <footer class="footer"><span>FAULTLINE <span aria-hidden="true">/</span> BUILT FOR DEFENDERS.</span><span>Declared dependencies ≠ runtime reachability.<br>Always validate in your environment.</span></footer></main></div></div>
    <dialog class="import-dialog" id="import-dialog" aria-labelledby="import-title"><div class="modal-header"><div><div class="eyebrow">OPEN AN INVESTIGATION</div><h2 id="import-title">Start with your inventory.</h2></div><button class="close" data-close aria-label="Close import">×</button></div><form id="import-form" class="modal-body">
      <label class="upload-zone">${icon("upload", 24)}<strong>A small file. A wider view.</strong><span>CycloneDX 1.4–1.7 or SPDX 2.2/2.3 · JSON · up to 8 MiB</span><input type="file" id="sbom-file" accept=".json,application/json" required aria-label="SBOM file"></label>
      <div class="form-row"><label><span class="form-label">EXPOSURE</span><select id="exposure"><option value="unknown">Unknown / not assessed</option><option value="internet">Internet-facing</option><option value="internal">Internal</option></select></label><label><span class="form-label">BUSINESS CRITICALITY</span><select id="criticality"><option value="standard">Standard</option><option value="critical">Critical</option></select></label></div>
      <div class="form-label">INTELLIGENCE SOURCE</div><div class="radio-group"><label><input type="radio" name="mode" value="live" checked> Live intelligence</label><label><input type="radio" name="mode" value="snapshot"> Saved evidence (offline)</label></div>
      <div id="live-options"><label class="consent"><input type="checkbox" id="consent"><span>Send package names and versions to <b>OSV</b> and CVE IDs to <b>FIRST</b>. Download CISA’s KEV catalog. The full SBOM stays in this local process; no files are stored by Faultline.</span></label></div>
      <div id="snapshot-options" class="hidden"><label class="form-label" for="snapshot-file">FAULTLINE EVIDENCE SNAPSHOT</label><input type="file" id="snapshot-file" accept=".json,application/json"><p class="help">Replay a previously exported evidence file. No external connections.</p></div>
      <div id="import-error" class="error-message" role="alert"></div><div id="import-progress" class="progress-message" role="status"></div><div class="modal-footer"><a href="/example.json" download="harbor.cdx.json" class="help">Download sample SBOM ↗</a><button class="btn dark" id="analyze-button" type="submit">Investigate ${icon("arrow", 14)}</button></div></form></dialog>
    <dialog class="detail-dialog" id="detail-dialog" aria-labelledby="detail-title"></dialog>
    <dialog class="export-dialog" id="export-dialog" aria-labelledby="export-title"><div class="modal-header"><div><div class="eyebrow">TAKE THE EVIDENCE WITH YOU</div><h2 id="export-title">An investigation, portable.</h2></div><button class="close" data-close aria-label="Close export">×</button></div><div class="modal-body export-grid"><button class="export-option" data-download="markdown"><strong>The briefing</strong><span>Markdown report with priorities and decision rationale ↗</span></button><button class="export-option" data-download="json"><strong>The full record</strong><span>Structured JSON · findings, graph, context and evidence hash ↗</span></button><button class="export-option" data-download="sarif"><strong>The developer handoff</strong><span>SARIF 2.1.0 for security tooling ↗</span></button><button class="export-option" data-download="snapshot"><strong>The evidence capsule</strong><span>Replayable snapshot for offline investigations ↗</span></button></div></dialog>`;
  bind();
  if (view === "overview") drawGraph();
}
function overview(): string {
  const r = bundle.report,
    n = counts(),
    top = r.findings[0],
    kevCount = r.findings.filter((f) => f.kev).length;
  return `<div class="status-strip"><span><b>${esc(r.inventory.name)}</b></span><span>${r.inventory.format} · ${r.coverage.total} components</span><span><b>${r.coverage.queried}/${r.coverage.queryable}</b> queried · ${r.coverage.skipped} skipped</span><span class="right mono">EVIDENCE / ${esc(r.evidence.acquiredAt.slice(0, 10))}</span></div>
    <section class="stats" aria-label="Investigation summary"><div class="stat"><div class="stat-head">Vulnerability instances</div><div class="stat-number">${String(r.findings.length).padStart(2, "0")}<span class="annotation">${r.plan.length} components</span></div><small>Advisory aliases merged per component</small></div><div class="stat"><div class="stat-head">Known exploitation</div><div class="stat-number accent-text">${String(kevCount).padStart(2, "0")}<span class="annotation">CISA KEV</span></div><small>In available catalog evidence</small></div><div class="stat"><div class="stat-head">Expedited review</div><div class="stat-number">${String(n.P1).padStart(2, "0")}<span class="annotation">P1</span></div><small>Severity, likelihood or exposure</small></div><div class="stat"><div class="stat-head">Repair work items</div><div class="stat-number">${String(r.plan.length).padStart(2, "0")}<span class="annotation">${r.inventory.components.length} in scope</span></div><small>Grouped by affected component</small></div></section>
    <div class="overview-grid"><section class="panel" aria-labelledby="graph-title"><div class="panel-header"><h2 class="panel-title" id="graph-title">The dependency terrain</h2><span class="panel-label">DECLARED RELATIONSHIPS</span></div><div class="graph-container"><svg class="graph" id="dependency-graph" viewBox="0 0 640 280" role="group" aria-label="Dependency graph. Select a component to inspect its findings."></svg><div id="graph-tooltip" class="graph-tooltip" role="status"></div></div><div class="graph-legend"><span><i class="legend-square hot"></i> Finding present</span><span><i class="legend-square"></i> No finding observed</span><span>SELECT TO INSPECT ↗</span></div></section>
    <section class="panel focus-card"><div class="focus-kicker"><span>THE FIRST MOVE</span><span>↗</span></div><h2>${top ? (top.kev ? "Start where exploitation is known." : "Put the strongest signal first.") : "A quieter queue.<br>Keep the context."}</h2><p>${top ? `${esc(comp(top.componentId).name)} carries ${esc(top.id)}. ${top.kev ? "Known exploitation makes this the first review in your repair plan." : "Its available evidence puts it at the head of this investigation."}` : "No vulnerabilities were returned for the queried components. Check coverage and evidence freshness before drawing conclusions."}</p><div class="focus-pills">${top ? `<span>${esc(top.id)}</span><span>${top.priority} / ${top.kev ? "KNOWN EXPLOITATION" : top.severity}</span>` : `<span>${r.coverage.queried}/${r.coverage.queryable} QUERIED</span>`}</div><div class="focus-footer"><span>${top ? `${String(1).padStart(2, "0")} / ${String(r.plan.length).padStart(2, "0")} WORK ITEMS` : "EVIDENCE FIRST"}</span><button ${top ? `data-finding="${top.key}"` : 'data-view="evidence"'}>${top ? "Inspect finding" : "Review coverage"} ${icon("arrow", 16)}</button></div></section></div>${queue(false)}`;
}
function filtered(): Finding[] {
  return bundle.report.findings.filter((f) => {
    const c = comp(f.componentId);
    return (
      (filter === "all" ||
        (filter === "kev" ? !!f.kev : f.priority === filter)) &&
      (!selectedComponent || f.componentId === selectedComponent) &&
      `${f.id} ${f.aliases.join(" ")} ${f.summary} ${c.name} ${c.version}`
        .toLowerCase()
        .includes(query.toLowerCase())
    );
  });
}
function queue(full: boolean): string {
  const items = filtered(),
    size = full ? 20 : 5,
    start = page * size,
    rows = items.slice(start, start + size);
  return `<section class="queue" aria-labelledby="queue-title"><div class="queue-heading"><div class="queue-title"><h2 id="queue-title">${full ? "The findings ledger" : "The priority queue"}</h2><span class="count">${items.length} INSTANCE${items.length === 1 ? "" : "S"}</span></div><div class="queue-tools"><label class="sr-only" for="search">Search findings</label><input id="search" class="search" placeholder="Search advisory or component…" value="${esc(query)}"><label class="sr-only" for="priority-filter">Filter priority</label><select class="select" id="priority-filter">${[
    ["all", "All priorities"],
    ["P0", "P0 · Immediate"],
    ["P1", "P1 · Expedite"],
    ["P2", "P2 · Prioritize"],
    ["P3", "P3 · Routine"],
    ["kev", "KEV only"],
  ]
    .map(
      ([v, text]) =>
        `<option value="${v}" ${filter === v ? "selected" : ""}>${text}</option>`,
    )
    .join("")}</select></div></div>
    ${selectedComponent ? `<div class="notice">Filtered to ${esc(comp(selectedComponent).name)} <button id="clear-component" class="text-button">Clear component filter</button></div>` : ""}
    <div class="table-scroll"><table class="findings-table"><thead><tr><th scope="col">Priority</th><th scope="col">Advisory / vulnerability</th><th scope="col">Component</th><th scope="col">EPSS · 30 days</th><th scope="col"><span class="sr-only">Details</span></th></tr></thead><tbody>${rows.map((f) => `<tr><td>${priority(f)}</td><td><button class="finding-link" data-finding="${f.key}">${esc(f.id)}</button>${f.kev ? '<span class="kev-label">KEV ↗</span>' : ""}<div class="finding-summary">${esc(f.summary)}</div></td><td><div class="component-name">${esc(comp(f.componentId).name)}</div><div class="component-version">${esc(comp(f.componentId).version)} <span aria-hidden="true">/</span> ${esc(f.severity.toLowerCase())}</div></td><td><div class="epss-value">${f.epss ? (f.epss.epss * 100).toFixed(2) + "%" : "Unknown"}</div>${f.epss ? `<progress class="epss-bar" max="1" value="${f.epss.epss}" aria-label="EPSS probability"></progress>` : ""}</td><td><button class="arrow-button" data-finding="${f.key}" aria-label="Inspect ${esc(f.id)} in ${esc(comp(f.componentId).name)}">↗</button></td></tr>`).join("") || `<tr><td colspan="5"><div class="empty"><h3>${query || filter !== "all" ? "No matching findings." : "No findings observed."}</h3><p>${query || filter !== "all" ? "Try another search or priority filter." : "This applies only to the queried inventory and available evidence. Review coverage."}</p></div></td></tr>`}</tbody></table></div>
    <div class="table-footer"><span>${items.length ? `${start + 1}–${Math.min(start + size, items.length)} OF ${items.length}` : "0 FINDINGS"} <span aria-hidden="true">/</span> ORDERED BY PRIORITY, THEN SIGNAL</span><div>${full && items.length > size ? `<button class="text-button" id="prev-page" ${page === 0 ? "disabled" : ""}>← Previous</button> <button class="text-button" id="next-page" ${start + size >= items.length ? "disabled" : ""}>Next →</button>` : !full ? '<button class="text-button" data-view="findings">Open full ledger →</button>' : "EACH RANK IS EXPLAINABLE"}</div></div></section>`;
}
function plan(): string {
  return `<p class="intro">Work items group the observed findings by component. Advisory fixed versions are candidates to investigate, not a promise that one upgrade resolves every issue. Use the appropriate release branch, test compatibility, and rescan.</p><div class="plan-grid">${
    bundle.report.plan
      .map((task, i) => {
        const c = comp(task.componentId),
          findings = bundle.report.findings.filter((f) =>
            task.findingKeys.includes(f.key),
          );
        return `<article class="panel plan-card"><div class="step">${String(i + 1).padStart(2, "0")}<span aria-hidden="true">—</span></div><div>${priority(task)}</div><h3>${esc(c.name)}</h3><p>Review ${findings.length} finding${findings.length === 1 ? "" : "s"} affecting version <b>${esc(c.version)}</b>. ${findings.some((f) => f.kev) ? "Known exploitation is present in the available evidence." : "Validate the advisory conditions against your deployment."}</p><div class="plan-meta">${findings.map((f) => esc(f.id)).join("<br>")}</div><button class="btn" data-finding="${findings[0]!.key}">Open evidence ${icon("arrow", 13)}</button></article>`;
      })
      .join("") ||
    '<div class="empty"><h3>No repair work items.</h3><p>Review evidence coverage before closing the investigation.</p></div>'
  }</div>`;
}
function inventory(): string {
  const r = bundle.report;
  return `<p class="intro">${r.coverage.total} components · ${r.inventory.edges.length} declared edges · ${r.inventory.roots.length} application roots. Unsupported or unversioned Package URLs remain visible as coverage gaps. “No finding observed” applies to queried versions, not an assertion of safety.</p><div class="table-scroll"><table class="findings-table inventory-table"><thead><tr><th>Component</th><th>Version</th><th>Ecosystem</th><th>Query coverage</th><th>Findings</th></tr></thead><tbody>${r.inventory.components
    .map((c) => {
      const q = c.purl
        ? bundle.snapshot.queries.find((q) => q.purl === c.purl)
        : null;
      const count = r.findings.filter((f) => f.componentId === c.id).length;
      return `<tr><td><b>${esc(c.name)}</b><div class="component-version">${esc(c.id)}</div></td><td class="mono">${esc(c.version || "Unknown")}</td><td>${esc(c.ecosystem ?? "Unspecified")}</td><td>${!c.purl ? "Skipped · no supported versioned PURL" : q?.status === "ok" ? "Queried" : "Incomplete / not queried"}</td><td>${count ? `<button class="text-button" data-component="${esc(c.id)}">${count} instance${count === 1 ? "" : "s"} ↗</button>` : "None observed"}</td></tr>`;
    })
    .join("")}</tbody></table></div>`;
}
function evidence(): string {
  const r = bundle.report,
    s = bundle.snapshot;
  return `<div class="evidence-grid"><article class="panel source-card"><span class="source-status ${r.coverage.queried < r.coverage.queryable ? "error" : ""}">${r.coverage.queried}/${r.coverage.queryable} COMPONENTS QUERIED</span><h3>OSV.dev</h3><p>Version-specific advisory matches. ${s.advisories.length} advisory records preserved. Withdrawn records are excluded from findings. ${r.coverage.skipped} components skipped.</p></article><article class="panel source-card"><span class="source-status ${s.kev.status === "error" ? "error" : ""}">${s.kev.status === "ok" ? "CATALOG AVAILABLE" : "UNAVAILABLE"}</span><h3>CISA KEV</h3><p>Evidence of known exploitation. ${s.kev.entries.length} catalog entries in this snapshot. An absent match does not establish that exploitation has never occurred.</p></article><article class="panel source-card"><span class="source-status ${s.epss.status === "error" ? "error" : ""}">${s.epss.status === "ok" ? "DATA AVAILABLE" : "UNAVAILABLE"}</span><h3>FIRST EPSS</h3><p>${s.epss.entries.length} probabilities preserved. A 30-day exploitation estimate for a CVE, not the probability of compromise of this application. Missing scores stay unknown.</p></article></div><div class="evidence-details"><section class="panel notes"><h3>The chain of evidence</h3><div class="eyebrow">INPUT / SHA-256</div><div class="hash">${r.inventory.inputHash}</div><div class="eyebrow">CANONICAL EVIDENCE / SHA-256</div><div class="hash">${r.evidence.hash}</div><p class="help">Acquired: ${esc(r.evidence.acquiredAt)}<br>Report generated: ${esc(r.generatedAt)}<br>Mode: ${r.evidence.mode} · ${r.complete ? "Queries and enrichment complete" : "Incomplete / stale / review required"}<br>Hashes identify content. They do not authenticate the source.</p><div class="dialog-actions"><button class="btn" data-download="snapshot">${icon("download", 13)} Save evidence</button><button class="btn" data-view="method">Inspect policy ${icon("arrow", 13)}</button></div></section><section class="panel notes"><h3>What the evidence cannot tell us</h3><ul>${r.warnings.map((w) => `<li>${esc(w)}</li>`).join("") || "<li>No parser or provider warnings. Dependency and code reachability still require independent validation.</li>"}</ul></section></div>`;
}
function method(): string {
  return `<div class="about-layout"><section class="panel method"><div class="eyebrow">PRIORITIZATION / POLICY V1</div><h3>Signals first. Then judgment.</h3><p>Faultline assigns a review priority to each advisory instance. The policy is deterministic and inspectable. It is an operational triage heuristic, not a validated probability model or a replacement for deployment-specific analysis.</p><ol class="method-list"><li><span class="priority P0">P0</span><div>Known exploitation<span>A CVE alias matches a CISA KEV entry. Review immediately regardless of severity.</span></div></li><li><span class="priority P1">P1</span><div>Expedited review<span>EPSS ≥ 10%, critical severity, or high severity combined with internet exposure / critical business context.</span></div></li><li><span class="priority P2">P2</span><div>Prioritized review<span>High severity without a P1 trigger, or severity is unknown and needs manual investigation.</span></div></li><li><span class="priority P3">P3</span><div>Routine review<span>Lower severity and no available higher-priority exploitation signal. This is not a safety verdict.</span></div></li></ol><p>Within a priority, sorting points are KEV × 60 + EPSS × 20 + severity × 1.5 (CVSS base, when known) + context up to 5. Label-only severity maps to 3.75 / 7.5 / 11.25 / 15 points. Unknown contributes 0 points and remains P2 unless another signal elevates it. The points do not represent risk probability.</p><div class="method-links"><a href="https://google.github.io/osv.dev/" target="_blank" rel="noopener noreferrer">OSV API ↗</a><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">CISA KEV ↗</a><a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">FIRST EPSS ↗</a></div></section><section class="panel method"><div class="eyebrow">SCOPE & HONEST BOUNDARIES</div><h3>A map is a starting point.</h3><p>Dependency paths follow the SBOM’s declared graph. They do not prove that vulnerable code executes, that an exploit precondition holds, or that a workload is internet reachable.</p><p>Fixed candidates are OSV advisory range endpoints for the matched package. They are not ecosystem-aware upgrade plans. Check branch applicability, release notes, and the other findings affecting that component.</p><p>Live intelligence is opt-in. This process queries fixed HTTPS endpoints, never executes input code, and keeps no persistent inventory database. Treat exported reports as potentially sensitive.</p><p>CI gates are indeterminate when evidence is stale, incomplete, or illustrative. Skipped inventory is always disclosed; a gate result covers queried packages only.</p><button class="btn dark" id="method-import">Start an investigation ${icon("arrow", 13)}</button></section></div>`;
}
function bind(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-view]").forEach(
    (el) =>
      (el.onclick = () => {
        selectedComponent = null;
        query = "";
        filter = "all";
        setView(el.dataset.view as View);
      }),
  );
  for (const id of ["top-import", "demo-import", "method-import"])
    document
      .getElementById(id)
      ?.addEventListener("click", () =>
        document
          .querySelector<HTMLDialogElement>("#import-dialog")!
          .showModal(),
      );
  document
    .querySelector("#export")
    ?.addEventListener("click", () =>
      document.querySelector<HTMLDialogElement>("#export-dialog")!.showModal(),
    );
  document.querySelector("#reload-demo")?.addEventListener("click", () => {
    void loadDemo();
  });
  document
    .querySelectorAll<HTMLButtonElement>("[data-close]")
    .forEach((el) => (el.onclick = () => el.closest("dialog")!.close()));
  document
    .querySelectorAll<HTMLButtonElement>("[data-finding]")
    .forEach((el) => (el.onclick = () => showFinding(el.dataset.finding!)));
  document.querySelectorAll<HTMLButtonElement>("[data-component]").forEach(
    (el) =>
      (el.onclick = () => {
        selectedComponent = el.dataset.component!;
        query = "";
        filter = "all";
        setView("findings");
      }),
  );
  document
    .querySelectorAll<HTMLButtonElement>("[data-download]")
    .forEach((el) => (el.onclick = () => download(el.dataset.download!)));
  document
    .querySelector<HTMLSelectElement>("#priority-filter")
    ?.addEventListener("change", (e) => {
      filter = (e.target as HTMLSelectElement).value;
      page = 0;
      replaceQueue();
    });
  document
    .querySelector<HTMLInputElement>("#search")
    ?.addEventListener("input", (e) => {
      query = (e.target as HTMLInputElement).value;
      page = 0;
      replaceQueue(true);
    });
  document.querySelector("#clear-component")?.addEventListener("click", () => {
    selectedComponent = null;
    page = 0;
    render();
  });
  document.querySelector("#prev-page")?.addEventListener("click", () => {
    page--;
    render();
  });
  document.querySelector("#next-page")?.addEventListener("click", () => {
    page++;
    render();
  });
  document.querySelectorAll<HTMLInputElement>('input[name="mode"]').forEach(
    (input) =>
      (input.onchange = () => {
        const offline = input.value === "snapshot";
        document
          .querySelector("#live-options")!
          .classList.toggle("hidden", offline);
        document
          .querySelector("#snapshot-options")!
          .classList.toggle("hidden", !offline);
      }),
  );
  document.querySelector<HTMLFormElement>("#import-form")!.onsubmit = (e) => {
    e.preventDefault();
    void submitImport();
  };
}
function replaceQueue(restoreSearch = false): void {
  const old = document.querySelector(".queue")!;
  old.outerHTML = queue(view === "findings");
  // Rebind only controls inside the queue to preserve open dialogs and focus.
  const root = document.querySelector(".queue")!;
  root
    .querySelectorAll<HTMLButtonElement>("[data-finding]")
    .forEach((el) => (el.onclick = () => showFinding(el.dataset.finding!)));
  root
    .querySelector("[data-view]")
    ?.addEventListener("click", () => setView("findings"));
  root.querySelector("#clear-component")?.addEventListener("click", () => {
    selectedComponent = null;
    replaceQueue();
  });
  root.querySelector("#prev-page")?.addEventListener("click", () => {
    page--;
    replaceQueue();
  });
  root.querySelector("#next-page")?.addEventListener("click", () => {
    page++;
    replaceQueue();
  });
  root.querySelector<HTMLSelectElement>("#priority-filter")!.onchange = (e) => {
    filter = (e.target as HTMLSelectElement).value;
    page = 0;
    replaceQueue();
    document.querySelector<HTMLSelectElement>("#priority-filter")!.focus();
  };
  root.querySelector<HTMLInputElement>("#search")!.oninput = (e) => {
    query = (e.target as HTMLInputElement).value;
    page = 0;
    replaceQueue(true);
  };
  if (restoreSearch) {
    const input = document.querySelector<HTMLInputElement>("#search")!;
    input.focus();
    input.setSelectionRange(query.length, query.length);
  }
}
function showFinding(key: string): void {
  const f = bundle.report.findings.find((f) => f.key === key)!;
  if (!f) return;
  const c = comp(f.componentId),
    d = document.querySelector<HTMLDialogElement>("#detail-dialog")!;
  d.innerHTML = `<div class="modal-header"><div><div class="eyebrow">FINDING / ${esc(c.name)}@${esc(c.version)}</div><h2 id="detail-title">${esc(f.id)}</h2></div><button class="close" data-close aria-label="Close finding">×</button></div><div class="detail-main">${priority(f)}<div class="detail-summary">${esc(f.summary)}</div><div class="detail-metrics"><div><span class="eyebrow">SEVERITY</span><b>${f.cvss !== null ? f.cvss.toFixed(1) : esc(f.severity)}</b></div><div><span class="eyebrow">EPSS / 30 DAYS</span><b>${f.epss ? (f.epss.epss * 100).toFixed(2) + "%" : "Unknown"}</b></div><div><span class="eyebrow">CISA KEV</span><b>${f.kev ? "Listed" : bundle.report.evidence.kev === "ok" ? "No match" : "Unknown"}</b></div></div>
  <section class="detail-section"><h3>Why this priority</h3><ul class="rationale">${f.reasons.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>${f.epss ? `<p>EPSS date: ${esc(f.epss.date)} · percentile ${(f.epss.percentile * 100).toFixed(2)}%. Percentile is a rank, not an exploitation probability.</p>` : ""}</section>
  <section class="detail-section"><h3>Declared dependency path</h3><div class="path">${f.path.map((id) => `<span>${esc(comp(id).name)}</span>`).join('<b aria-hidden="true">→</b>') || "<p>No path available from the declared application root.</p>"}</div><p>${f.dependents} upstream component${f.dependents === 1 ? " depends" : "s depend"} on this component in the declared graph. Runtime reachability remains unknown.</p></section>
  <section class="detail-section"><h3>Repair investigation</h3><div class="fixed">${f.fixed.length ? `Fixed version candidates: ${f.fixed.map(esc).join(" · ")}` : "No fixed version candidates supplied for this package."}</div><p>These are advisory range endpoints. Check release branch applicability and compatibility. Review all findings on this component and rescan after changing it.</p>${f.kev ? `<p><b>CISA action:</b> ${esc(f.kev.requiredAction)}<br>Catalog added: ${esc(f.kev.dateAdded)} · catalog due date: ${esc(f.kev.dueDate)} (not a deadline assigned to this project).</p>` : ""}</section>
  <section class="detail-section"><h3>Advisory notes</h3><pre>${esc(f.details || "No additional description supplied.")}</pre></section><section class="detail-section"><h3>Source references</h3><div class="reference-links">${f.references.map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)} ↗</a>`).join("") || "<p>No source links supplied.</p>"}</div><p>Aliases: ${f.aliases.map(esc).join(" · ")}<br>Original records: ${f.advisoryIds.map(esc).join(" · ")}</p></section><div class="dialog-actions"><button class="btn dark" id="component-findings">All component findings ${icon("arrow", 13)}</button><button class="btn" id="detail-export">${icon("download", 13)} Export full report</button></div></div>`;
  d.querySelector("[data-close]")!.addEventListener("click", () => d.close());
  d.querySelector("#component-findings")!.addEventListener("click", () => {
    d.close();
    selectedComponent = c.id;
    query = "";
    filter = "all";
    setView("findings");
  });
  d.querySelector("#detail-export")!.addEventListener("click", () =>
    download("markdown"),
  );
  d.showModal();
}
async function submitImport(): Promise<void> {
  const form = document.querySelector<HTMLFormElement>("#import-form")!,
    button = document.querySelector<HTMLButtonElement>("#analyze-button")!;
  const error = document.querySelector("#import-error")!,
    progress = document.querySelector("#import-progress")!;
  error.textContent = "";
  const file =
    document.querySelector<HTMLInputElement>("#sbom-file")!.files?.[0];
  if (!file) return;
  const mode = new FormData(form).get("mode");
  try {
    if (file.size > 8 * 1024 * 1024)
      throw new Error("SBOM exceeds the 8 MiB limit.");
    const consent =
      document.querySelector<HTMLInputElement>("#consent")!.checked;
    if (mode === "live" && !consent)
      throw new Error(
        "Confirm the intelligence query disclosure or choose saved evidence.",
      );
    let snapshot: unknown;
    if (mode === "snapshot") {
      const evidence =
        document.querySelector<HTMLInputElement>("#snapshot-file")!.files?.[0];
      if (!evidence) throw new Error("Select a Faultline evidence snapshot.");
      if (evidence.size > 8 * 1024 * 1024)
        throw new Error("Evidence file exceeds 8 MiB.");
      snapshot = JSON.parse(await evidence.text()) as unknown;
    }
    button.disabled = true;
    progress.innerHTML = `<span class="spinner" aria-hidden="true"></span> ${mode === "live" ? "Querying intelligence and assembling evidence. This can take a few minutes…" : "Replaying evidence and tracing dependencies…"}`;
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Faultline-Request": "1",
      },
      body: JSON.stringify({
        inventory: await file.text(),
        mode,
        consent,
        snapshot,
        context: {
          exposure:
            document.querySelector<HTMLSelectElement>("#exposure")!.value,
          criticality:
            document.querySelector<HTMLSelectElement>("#criticality")!.value,
        },
      }),
    });
    const result = (await response.json()) as ResponseBundle & {
      error?: string;
    };
    if (!response.ok) throw new Error(result.error ?? "Analysis failed.");
    bundle = result;
    query = "";
    filter = "all";
    page = 0;
    selectedComponent = null;
    view = "overview";
    document.querySelector<HTMLDialogElement>("#import-dialog")!.close();
    render();
    toast("Investigation ready. Review evidence coverage before acting.");
  } catch (e) {
    error.textContent =
      e instanceof Error ? e.message : "Could not complete the investigation.";
    progress.textContent = "";
  } finally {
    button.disabled = false;
  }
}
function download(kind: string): void {
  const formats: Record<
    string,
    { data: unknown; extension: string; type: string }
  > = {
    json: {
      data: bundle.report,
      extension: "report.json",
      type: "application/json",
    },
    markdown: {
      data: bundle.exports.markdown,
      extension: "brief.md",
      type: "text/markdown",
    },
    sarif: {
      data: bundle.exports.sarif,
      extension: "sarif.json",
      type: "application/json",
    },
    snapshot: {
      data: bundle.snapshot,
      extension: "evidence.json",
      type: "application/json",
    },
  };
  const f = formats[kind];
  if (!f) return;
  const blob = new Blob(
    [typeof f.data === "string" ? f.data : JSON.stringify(f.data, null, 2)],
    { type: f.type },
  );
  const url = URL.createObjectURL(blob),
    a = document.createElement("a");
  a.href = url;
  a.download = `faultline-${f.extension}`;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast("Export prepared. Treat inventory reports as sensitive.");
}
function toast(message: string): void {
  document.querySelector(".toast")?.remove();
  const el = document.createElement("div");
  el.className = "toast";
  el.setAttribute("role", "status");
  el.textContent = message;
  document.body.append(el);
  setTimeout(() => el.remove(), 5000);
}
function drawGraph(): void {
  const r = bundle.report,
    svg = document.querySelector<SVGSVGElement>("#dependency-graph")!;
  const nodes = r.inventory.components.slice(0, 60),
    ids = new Set(nodes.map((n) => n.id));
  const levels = new Map<string, number>();
  const todo = r.inventory.roots.filter((id) => ids.has(id));
  for (const id of todo) levels.set(id, 0);
  const adjacency = new Map<string, string[]>();
  for (const [a, b] of r.inventory.edges)
    adjacency.set(a, [...(adjacency.get(a) ?? []), b]);
  for (let i = 0; i < todo.length; i++)
    for (const next of adjacency.get(todo[i]!) ?? [])
      if (ids.has(next) && !levels.has(next)) {
        levels.set(next, Math.min(4, levels.get(todo[i]!)! + 1));
        todo.push(next);
      }
  for (const n of nodes) if (!levels.has(n.id)) levels.set(n.id, 4);
  const grouped = new Map<number, Component[]>();
  for (const n of nodes) {
    const l = levels.get(n.id)!;
    grouped.set(l, [...(grouped.get(l) ?? []), n]);
  }
  const pos = new Map<string, [number, number]>(),
    max = Math.max(1, ...grouped.keys());
  for (const [level, group] of grouped)
    group.forEach((n, i) =>
      pos.set(n.id, [
        48 + (level / max) * 420,
        25 + ((i + 1) / (group.length + 1)) * 225,
      ]),
    );
  const hot = new Set(r.findings.map((f) => f.componentId));
  const edges = r.inventory.edges.filter(([a, b]) => ids.has(a) && ids.has(b));
  svg.innerHTML = `<title>Declared dependency graph for ${esc(r.inventory.name)}</title><desc>${nodes.length} components shown${r.coverage.total > 60 ? ` out of ${r.coverage.total}; view Inventory for all components` : ""}. Warm nodes have findings. Select a node to filter findings.</desc>${edges
    .map(([a, b]) => {
      const [x1, y1] = pos.get(a)!,
        [x2, y2] = pos.get(b)!;
      return `<path class="edge ${hot.has(b) ? "hot" : ""}" d="M${x1} ${y1}C${(x1 + x2) / 2} ${y1},${(x1 + x2) / 2} ${y2},${x2} ${y2}"/>`;
    })
    .join("")}${nodes
    .map((n) => {
      const [x, y] = pos.get(n.id)!;
      const root = r.inventory.roots.includes(n.id);
      const label = n.name.length > 19 ? n.name.slice(0, 17) + "…" : n.name;
      return `<g class="node ${root ? "root" : ""} ${hot.has(n.id) ? "hot" : ""}" data-graph-id="${esc(n.id)}" role="button" tabindex="0" aria-label="${esc(n.name)}: ${r.findings.filter((f) => f.componentId === n.id).length} findings" transform="translate(${x},${y})"><title>${esc(n.name)}@${esc(n.version)}</title><circle r="${root ? 9 : hot.has(n.id) ? 7 : 5}"/><text x="${root ? -3 : 12}" y="${root ? 25 : 3}" text-anchor="${root ? "middle" : "start"}">${esc(label)}</text></g>`;
    })
    .join("")}`;
  svg.querySelectorAll<SVGGElement>("[data-graph-id]").forEach((el) => {
    const id = el.dataset.graphId!,
      n = comp(id),
      count = r.findings.filter((f) => f.componentId === id).length;
    const show = (): void => {
      const tip = document.querySelector("#graph-tooltip")!;
      tip.textContent = `${n.name}@${n.version || "unknown"} · ${count} findings · select to open ledger`;
      tip.classList.add("visible");
    };
    const hide = (): void =>
      document.querySelector("#graph-tooltip")!.classList.remove("visible");
    const select = (): void => {
      selectedComponent = id;
      query = "";
      filter = "all";
      setView("findings");
    };
    el.onmouseenter = show;
    el.onmouseleave = hide;
    el.onfocus = show;
    el.onblur = hide;
    el.onclick = select;
    el.onkeydown = (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        select();
      }
    };
  });
}
async function loadDemo(): Promise<void> {
  try {
    const response = await fetch("/api/demo");
    if (!response.ok)
      throw new Error("Could not open the sample investigation.");
    bundle = (await response.json()) as ResponseBundle;
    query = "";
    filter = "all";
    page = 0;
    selectedComponent = null;
    view = "overview";
    render();
  } catch (e) {
    app.innerHTML = `<div class="boot">FAULTLINE<span>${esc(e instanceof Error ? e.message : "Could not reach the local server.")} Restart the application and reload this page.</span></div>`;
  }
}
void loadDemo();
