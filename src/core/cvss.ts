/** CVSS v3.0/v3.1 base only. v2/v4 vectors deliberately remain unknown. */
export function cvss3(vector: string): number | null {
  const parts = vector.split("/");
  if (!["CVSS:3.0", "CVSS:3.1"].includes(parts.shift() ?? "")) return null;
  const m = new Map<string, string>();
  for (const part of parts) {
    const [key, value] = part.split(":");
    if (!key || !value || m.has(key)) return null;
    m.set(key, value);
  }
  const get = (
    key: string,
    weights: Record<string, number>,
  ): number | undefined => weights[m.get(key) ?? ""];
  const av = get("AV", { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }),
    ac = get("AC", { L: 0.77, H: 0.44 });
  const changed = m.get("S") === "C";
  if (!["U", "C"].includes(m.get("S") ?? "")) return null;
  const pr = get(
    "PR",
    changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 },
  );
  const ui = get("UI", { N: 0.85, R: 0.62 }),
    c = get("C", { H: 0.56, L: 0.22, N: 0 }),
    i = get("I", { H: 0.56, L: 0.22, N: 0 }),
    a = get("A", { H: 0.56, L: 0.22, N: 0 });
  if ([av, ac, pr, ui, c, i, a].includes(undefined)) return null;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  const raw = Math.min(10, (impact + exploitability) * (changed ? 1.08 : 1));
  // FIRST's integer-based Roundup avoids floating point boundary errors.
  const integer = Math.round(raw * 100000);
  return integer % 10000 === 0
    ? integer / 100000
    : (Math.floor(integer / 10000) + 1) / 10;
}
