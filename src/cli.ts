import { readFile, stat, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { analyze, validateContext } from "./core/analyze.js";
import { collectEvidence, validateSnapshot } from "./core/evidence.js";
import { parseInventory } from "./core/input.js";
import { gate, markdown, sarif } from "./core/reports.js";
import { InputError, parseJSON } from "./core/validation.js";
import type { Priority } from "./core/model.js";
const help = `Faultline 1.0 · evidence-led dependency triage

  node dist/src/cli.js analyze <sbom.json> [options]

  --evidence <snapshot.json>  Replay saved evidence without network access
  --live                     Query OSV, CISA KEV and FIRST EPSS (explicit opt-in)
  --exposure unknown|internal|internet   Default: unknown
  --criticality standard|critical       Default: standard
  --format json|markdown|sarif          Default: json
  --output <path>             Write report to file instead of stdout
  --save-evidence <path>      Save replayable normalized intelligence
  --fail-on P0|P1|P2|P3|none   Default: none; P1 blocks P0 and P1

Exit: 0 policy passed; 1 policy violated; 2 incomplete/stale/demo evidence; 3 input/runtime error.
Live mode sends package names/versions to OSV and CVE IDs to FIRST. It downloads the CISA catalog.
SBOM contents are never executed. No package installation or exploitation is performed.
`;
async function boundedRead(path: string): Promise<string> {
  if ((await stat(path)).size > 8 * 1024 * 1024)
    throw new InputError("File exceeds 8 MiB.");
  return readFile(path, "utf8");
}
async function main(): Promise<void> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      help: { type: "boolean", short: "h" },
      live: { type: "boolean" },
      evidence: { type: "string" },
      exposure: { type: "string", default: "unknown" },
      criticality: { type: "string", default: "standard" },
      format: { type: "string", default: "json" },
      output: { type: "string" },
      "save-evidence": { type: "string" },
      "fail-on": { type: "string", default: "none" },
    },
  });
  if (values.help || !positionals.length) {
    console.log(help);
    return;
  }
  if (
    positionals[0] !== "analyze" ||
    !positionals[1] ||
    positionals.length !== 2
  )
    throw new InputError("Use analyze <sbom.json>. See --help.");
  if (!!values.live === !!values.evidence)
    throw new InputError(
      "Choose exactly one of --live or --evidence <snapshot>.",
    );
  if (!["json", "markdown", "sarif"].includes(values.format!))
    throw new InputError("Format must be json, markdown, or sarif.");
  if (!["P0", "P1", "P2", "P3", "none"].includes(values["fail-on"]!))
    throw new InputError("Invalid --fail-on threshold.");
  const context = validateContext({
    exposure: values.exposure,
    criticality: values.criticality,
  });
  const inventory = parseInventory(await boundedRead(positionals[1]));
  const snapshot = values.live
    ? await collectEvidence(inventory)
    : validateSnapshot(parseJSON(await boundedRead(values.evidence!)));
  const report = analyze(inventory, snapshot, context);
  if (values["save-evidence"])
    await writeFile(
      values["save-evidence"],
      JSON.stringify(snapshot, null, 2) + "\n",
      { flag: "wx" },
    );
  const output =
    values.format === "markdown"
      ? markdown(report)
      : JSON.stringify(
          values.format === "sarif" ? sarif(report) : report,
          null,
          2,
        ) + "\n";
  if (values.output) await writeFile(values.output, output, { flag: "wx" });
  else process.stdout.write(output);
  const decision = gate(report, values["fail-on"] as Priority | "none");
  console.error(`Faultline: ${decision.reason}`);
  process.exitCode = decision.code;
}
main().catch((e) => {
  console.error(
    `Faultline: ${e instanceof Error ? e.message : "Unexpected failure."}`,
  );
  process.exitCode = 3;
});
