import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { createApp } from "../src/server.js";
test("HTTP boundary enforces Host, Origin, headers, offline policy and input validation", async () => {
  const server = createApp({ offline: true });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    let res = await fetch(base + "/api/health");
    assert.equal(res.status, 200);
    assert.equal(((await res.json()) as { offline: boolean }).offline, true);
    assert.ok(
      res.headers
        .get("content-security-policy")
        ?.includes("frame-ancestors 'none'"),
    );
    const hostileHost = await new Promise<number | undefined>(
      (resolve, reject) => {
        const req = httpRequest(
          base + "/api/health",
          { headers: { Host: "attacker.test" } },
          (response) => {
            response.resume();
            resolve(response.statusCode);
          },
        );
        req.on("error", reject);
        req.end();
      },
    );
    assert.equal(hostileHost, 403);
    res = await fetch(base + "/api/health", {
      headers: { Origin: "https://attacker.test" },
    });
    assert.equal(res.status, 403);
    res = await fetch(base + "/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(res.status, 403);
    const inventory = await readFile("examples/harbor.cdx.json", "utf8");
    const snapshot = JSON.parse(
      await readFile("examples/demo-evidence.json", "utf8"),
    ) as unknown;
    const request = (body: unknown) =>
      fetch(base + "/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Faultline-Request": "1",
        },
        body: JSON.stringify(body),
      });
    res = await request({ inventory, mode: "live", consent: true });
    assert.equal(res.status, 400);
    assert.ok(
      ((await res.json()) as { error: string }).error.includes("offline"),
    );
    res = await request({ inventory: "<script>", mode: "snapshot", snapshot });
    assert.equal(res.status, 400);
    res = await request({ inventory, mode: "snapshot", snapshot });
    assert.equal(res.status, 200);
    const data = (await res.json()) as {
      report: { findings: unknown[] };
      exports: { markdown: string };
    };
    assert.equal(data.report.findings.length, 6);
    assert.ok(data.exports.markdown.includes("DEMONSTRATION"));
    res = await fetch(base + "/api/demo");
    assert.equal(res.status, 200);
    res = await fetch(base + "/not-a-route");
    assert.equal(res.status, 404);
    res = await fetch(base + "/api/analyze", { method: "OPTIONS" });
    assert.equal(res.status, 404);
    assert.equal(res.headers.get("access-control-allow-origin"), null);
  } finally {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }
});
