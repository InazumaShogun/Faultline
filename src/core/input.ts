import type { Component, Inventory } from "./model.js";
import {
  arr,
  InputError,
  obj,
  parseJSON,
  required,
  sha256,
  str,
} from "./validation.js";
const ecosystems: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  maven: "Maven",
  golang: "Go",
  cargo: "crates.io",
  nuget: "NuGet",
  gem: "RubyGems",
  composer: "Packagist",
  hex: "Hex",
  pub: "Pub",
  swift: "SwiftURL",
};
export function parsePurl(
  value: unknown,
): { purl: string; name: string; version: string; ecosystem: string } | null {
  const p = str(value);
  if (!p) return null;
  // Qualifiers and subpaths are retained for inventory, but are not sent to OSV.
  const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)(?:\?[^#]*)?(?:#.*)?$/.exec(
    p,
  );
  if (!match || !match[1] || !match[2])
    throw new InputError(`Invalid Package URL: ${p.slice(0, 100)}`);
  const at = match[2].lastIndexOf("@");
  if (at <= 0 || at === match[2].length - 1) return null;
  const ecosystem = ecosystems[match[1]];
  if (!ecosystem) return null;
  try {
    let name = decodeURIComponent(match[2].slice(0, at));
    const version = decodeURIComponent(match[2].slice(at + 1));
    if (match[1] === "maven") {
      const slash = name.lastIndexOf("/");
      if (slash < 1) return null;
      name = `${name.slice(0, slash)}:${name.slice(slash + 1)}`;
    }
    if (match[1] === "pypi") name = name.toLowerCase().replace(/[-_.]+/g, "-");
    return { purl: `pkg:${match[1]}/${match[2]}`, name, version, ecosystem };
  } catch {
    throw new InputError("A Package URL contains invalid percent encoding.");
  }
}
export function parseInventory(text: string): Inventory {
  const data = obj(parseJSON(text), "SBOM");
  const components: Component[] = [],
    edges: [string, string][] = [],
    roots: string[] = [],
    warnings: string[] = [];
  const ids = new Set<string>();
  const add = (
    id: string,
    name: string,
    version: string,
    rawPurl: unknown,
    scope: string,
  ): void => {
    if (ids.has(id))
      throw new InputError(`Duplicate component identifier: ${id}`);
    if (ids.size >= 1500)
      throw new InputError(
        "This release supports at most 1,500 components per analysis.",
      );
    ids.add(id);
    const parsed = parsePurl(rawPurl);
    if (parsed && version && version !== parsed.version)
      throw new InputError(`Version disagrees with Package URL for ${name}.`);
    components.push({
      id,
      name,
      version: version || parsed?.version || "",
      purl: parsed?.purl ?? null,
      ecosystem: parsed?.ecosystem ?? null,
      scope,
    });
  };
  let name = str(data.name, "Imported inventory"),
    format: Inventory["format"];
  if (data.bomFormat === "CycloneDX") {
    if (!["1.4", "1.5", "1.6", "1.7"].includes(str(data.specVersion)))
      throw new InputError("Supported CycloneDX versions: 1.4–1.7 (JSON).");
    format = "CycloneDX";
    const walk = (items: unknown[], depth = 0): void => {
      if (depth > 30)
        throw new InputError("Nested components exceed 30 levels.");
      for (const raw of items) {
        const c = obj(raw, "component"),
          id =
            str(c["bom-ref"]) ||
            str(c.purl) ||
            `component-${components.length}`;
        add(
          id,
          required(c.name, "component.name"),
          str(c.version),
          c.purl,
          str(c.scope, "unspecified"),
        );
        walk(arr(c.components, "components", 1500), depth + 1);
      }
    };
    const metadata = data.metadata ? obj(data.metadata) : {};
    if (metadata.component) {
      const root = obj(metadata.component);
      name = str(root.name, name);
      walk([root]);
      roots.push(components[0]!.id);
    }
    walk(arr(data.components, "components", 1500));
    const declared = new Set<string>();
    for (const raw of arr(data.dependencies, "dependencies", 1500)) {
      const d = obj(raw),
        from = required(d.ref, "dependencies.ref");
      declared.add(from);
      for (const to of arr(d.dependsOn, "dependsOn", 1500))
        edges.push([from, required(to, "dependsOn")]);
    }
    const opaque = components.filter((c) => !declared.has(c.id)).length;
    if (opaque)
      warnings.push(
        `${opaque} components have no dependency declaration; missing edges are unknown, not proof of no dependencies.`,
      );
  } else if (
    typeof data.spdxVersion === "string" &&
    /^SPDX-2\.[23]$/.test(data.spdxVersion)
  ) {
    format = "SPDX";
    for (const raw of arr(data.packages, "packages", 1500)) {
      const p = obj(raw);
      const ref = arr(p.externalRefs)
        .map((r) => obj(r))
        .find((r) => r.referenceType === "purl");
      add(
        required(p.SPDXID, "SPDXID"),
        required(p.name, "package.name"),
        str(p.versionInfo),
        ref?.referenceLocator,
        "unspecified",
      );
    }
    for (const raw of arr(data.relationships, "relationships", 10000)) {
      const r = obj(raw),
        a = str(r.spdxElementId),
        b = str(r.relatedSpdxElement);
      if (r.relationshipType === "DEPENDS_ON") edges.push([a, b]);
      else if (r.relationshipType === "DEPENDENCY_OF") edges.push([b, a]);
      else if (r.relationshipType === "DESCRIBES" && ids.has(b)) roots.push(b);
      else if (r.relationshipType === "DESCRIBED_BY" && ids.has(a))
        roots.push(a);
    }
    for (const root of arr(data.documentDescribes))
      if (typeof root === "string" && ids.has(root)) roots.push(root);
    warnings.push(
      "SPDX relationship completeness is not inferred. Dependency paths describe declared relationships only.",
    );
  } else
    throw new InputError("Use a CycloneDX 1.4–1.7 or SPDX 2.2/2.3 JSON SBOM.");
  if (!components.length)
    throw new InputError("The SBOM contains no components.");
  const validEdges = edges.filter(([a, b]) => ids.has(a) && ids.has(b));
  if (validEdges.length !== edges.length)
    warnings.push(
      `${edges.length - validEdges.length} relationships reference missing/external components and were omitted.`,
    );
  if (validEdges.length > 15000)
    throw new InputError("Dependency graph exceeds 15,000 edges.");
  if (!roots.length)
    warnings.push(
      "No application root declared; paths from application entry points are unavailable.",
    );
  const skipped = components.filter((c) => !c.purl).length;
  if (skipped)
    warnings.push(
      `${skipped} components lack a supported, versioned Package URL and cannot be queried. See coverage before interpreting results.`,
    );
  return {
    name,
    format,
    components,
    edges: [...new Map(validEdges.map((e) => [JSON.stringify(e), e])).values()],
    roots: [...new Set(roots)],
    warnings,
    inputHash: sha256(text),
  };
}
