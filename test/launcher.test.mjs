import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, cp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep, basename } from "node:path";
import { spawn } from "node:child_process";
import { isFaultline, listenAvailable } from "../scripts/launch.mjs";

async function serve(handler) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, port: server.address().port };
}
const close = (server) =>
  new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  });
const run = (command, args, options) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      ...options,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      output += chunk;
    });
    child.on("error", reject);
    child.on("exit", (code) => resolve({ code, output }));
  });

test("launcher verifies and reuses an existing v1.0 instance without starting a second server", async () => {
  const { server, port } = await serve((req, res) => {
    if (req.url === "/api/health") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ status: "ok", version: "1.0.0" }));
    } else res.end("<html><head><title>Faultline - Test</title></head></html>");
  });
  try {
    assert.equal(await isFaultline(`http://127.0.0.1:${port}/`), true);
    const result = await run(process.execPath, ["scripts/launch.mjs"], {
      env: { ...process.env, PORT: String(port), FAULTLINE_NO_BROWSER: "1" },
    });
    assert.equal(result.code, 0);
    assert.match(result.output, /already running/);
  } finally {
    await close(server);
  }
});

test("launcher does not mistake another service for Faultline; it binds a free fallback port", async () => {
  const occupied = await serve((_req, res) => res.end("Another application"));
  let fallback;
  try {
    assert.equal(
      await isFaultline(`http://127.0.0.1:${occupied.port}/`),
      false,
    );
    fallback = await listenAvailable(() => createServer(), occupied.port, true);
    assert.notEqual(fallback.port, occupied.port);
    await assert.rejects(
      listenAvailable(() => createServer(), occupied.port, false),
      /occupied/,
    );
  } finally {
    if (fallback) await close(fallback.server);
    await close(occupied.server);
  }
});

test(
  "Windows batch launcher reports an invalid configuration and retains its failure prompt",
  { skip: process.platform !== "win32" },
  async () => {
    const result = await run("cmd.exe", ["/d", "/c", "start.cmd"], {
      env: { ...process.env, PORT: "invalid", FAULTLINE_NO_BROWSER: "1" },
    });
    assert.equal(result.code, 1);
    assert.match(result.output, /PORT must be/);
    assert.match(result.output, /error is shown above/);
  },
);

test(
  "Windows batch launcher explains when it was opened without the extracted project",
  { skip: process.platform !== "win32" },
  async () => {
    const folder = await mkdtemp(join(tmpdir(), "faultline-launcher-"));
    try {
      await cp("start.cmd", join(folder, "start.cmd"));
      const result = await run(
        "cmd.exe",
        ["/d", "/c", join(folder, "start.cmd")],
        { env: { ...process.env, FAULTLINE_NO_BROWSER: "1" } },
      );
      assert.equal(result.code, 1);
      assert.match(result.output, /Extract the entire ZIP/);
    } finally {
      assert.ok(resolve(folder).startsWith(resolve(tmpdir()) + sep));
      assert.ok(basename(folder).startsWith("faultline-launcher-"));
      await rm(folder, { recursive: true, force: true });
    }
  },
);
