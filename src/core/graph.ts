import type { Inventory } from "./model.js";
export class DependencyGraph {
  readonly forward = new Map<string, Set<string>>();
  readonly reverse = new Map<string, Set<string>>();
  private readonly parent = new Map<string, string | null>();
  constructor(inventory: Inventory) {
    for (const c of inventory.components) {
      this.forward.set(c.id, new Set());
      this.reverse.set(c.id, new Set());
    }
    for (const [a, b] of inventory.edges) {
      this.forward.get(a)?.add(b);
      this.reverse.get(b)?.add(a);
    }
    const queue = [...inventory.roots].sort();
    for (const r of queue) this.parent.set(r, null);
    for (let i = 0; i < queue.length; i++) {
      const current = queue[i]!;
      for (const next of [...(this.forward.get(current) ?? [])].sort())
        if (!this.parent.has(next)) {
          this.parent.set(next, current);
          queue.push(next);
        }
    }
  }
  pathTo(id: string): string[] {
    if (!this.parent.has(id)) return [];
    const path: string[] = [];
    for (
      let current: string | null = id;
      current !== null;
      current = this.parent.get(current) ?? null
    )
      path.push(current);
    return path.reverse();
  }
  dependents(id: string): Set<string> {
    const visited = new Set([id]),
      queue = [id];
    for (let i = 0; i < queue.length; i++)
      for (const p of this.reverse.get(queue[i]!) ?? [])
        if (!visited.has(p)) {
          visited.add(p);
          queue.push(p);
        }
    visited.delete(id);
    return visited;
  }
}
/** Alias components are merged transitively; advisory IDs remain available for audit. */
export function aliasGroups<T extends { id: string; aliases: string[] }>(
  records: T[],
): T[][] {
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    if (!parent.has(x)) parent.set(x, x);
    let root = x;
    while (parent.get(root) !== root) root = parent.get(root)!;
    while (parent.get(x) !== x) {
      const next = parent.get(x)!;
      parent.set(x, root);
      x = next;
    }
    return root;
  };
  for (const r of records)
    for (const alias of r.aliases) {
      const a = find(r.id),
        b = find(alias);
      if (a !== b) parent.set(b, a);
    }
  const groups = new Map<string, T[]>();
  for (const r of records) {
    const root = find(r.id);
    groups.set(root, [...(groups.get(root) ?? []), r]);
  }
  return [...groups.values()];
}
