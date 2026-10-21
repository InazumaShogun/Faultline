import type { Priority, Report } from "./model.js";
export function gate(
  report: Report,
  threshold: Priority | "none",
): { code: number; reason: string } {
  if (!report.complete || report.evidence.mode === "demo")
    return {
      code: 2,
      reason:
        "Evidence is incomplete, stale, or illustrative; release gate is indeterminate.",
    };
  if (
    threshold !== "none" &&
    report.findings.some((f) => f.priority <= threshold)
  )
    return {
      code: 1,
      reason: `Findings at or above ${threshold} violate policy.`,
    };
  return {
    code: 0,
    reason:
      "Policy passed for the queried inventory. Review skipped component coverage separately.",
  };
}
export function sarif(report: Report): unknown {
  const ids = [...new Set(report.findings.map((f) => f.id))];
  const components = new Map(report.inventory.components.map((c) => [c.id, c]));
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Faultline",
            version: "1.0.0",
            informationUri: "https://github.com/InazumaShogun/Faultline",
            rules: ids.map((id) => ({
              id,
              shortDescription: {
                text: report.findings.find((f) => f.id === id)!.summary,
              },
            })),
          },
        },
        invocations: [
          {
            executionSuccessful: report.complete,
            toolExecutionNotifications: report.warnings.map((message) => ({
              level: "warning",
              message: { text: message },
            })),
          },
        ],
        properties: {
          evidenceHash: report.evidence.hash,
          evidenceMode: report.evidence.mode,
          coverage: report.coverage,
        },
        results: report.findings.map((f) => ({
          ruleId: f.id,
          ruleIndex: ids.indexOf(f.id),
          level: f.priority <= "P1" ? "error" : "warning",
          message: {
            text: `${f.priority}: ${components.get(f.componentId)?.name}@${components.get(f.componentId)?.version}: ${f.summary}`,
          },
          partialFingerprints: { "faultline/v1": f.key },
          properties: {
            component: components.get(f.componentId)?.purl,
            priority: f.priority,
            epss: f.epss?.epss ?? null,
            knownExploited: f.kev !== null,
            fixedVersionCandidates: f.fixed,
            dependencyPath: f.path,
          },
        })),
      },
    ],
  };
}
const md = (s: string): string =>
  s
    .replace(/[\r\n|]/g, " ")
    .replace(/[<>]/g, "")
    .replace(/([\\`*_[\]])/g, "\\$1");
export function markdown(report: Report): string {
  const comps = new Map(report.inventory.components.map((c) => [c.id, c]));
  return `# Faultline · ${md(report.inventory.name)}\n\nGenerated: ${report.generatedAt}\n\nEvidence: **${report.evidence.mode}** · ${report.complete ? "query/enrichment complete" : "INCOMPLETE / STALE"}\n\nCoverage: ${report.coverage.queried}/${report.coverage.queryable} queryable components; ${report.coverage.skipped} skipped.\n\nInput SHA-256: \`${report.inventory.inputHash}\`\n\nEvidence SHA-256: \`${report.evidence.hash}\`\n\n## Remediation queue\n\n| Priority | Component | Advisory | Severity | EPSS | Fixed candidates |\n|---|---|---|---|---|---|\n${report.findings.map((f) => `| ${f.priority} | ${md(comps.get(f.componentId)?.name ?? "")}@${md(comps.get(f.componentId)?.version ?? "")} | ${md(f.id)} | ${f.severity} | ${f.epss ? (f.epss.epss * 100).toFixed(2) + "%" : "unknown"} | ${f.fixed.map(md).join(", ") || "not provided"} |`).join("\n")}\n\nFixed candidates are advisory range endpoints, not compatibility-tested upgrade recommendations. Declared dependency paths do not establish runtime reachability.\n\n## Evidence notes\n\n${report.warnings.map((w) => `- ${md(w)}`).join("\n")}\n\n## Decision rationale\n\n${report.findings.map((f) => `### ${md(f.id)} · ${md(comps.get(f.componentId)?.name ?? "")}\n\n${f.reasons.map((r) => `- ${md(r)}`).join("\n")}\n`).join("\n")}`;
}
