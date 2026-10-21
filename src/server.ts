import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { analyze, validateContext } from "./core/analyze.js";
import { collectEvidence, validateSnapshot } from "./core/evidence.js";
import { parseInventory } from "./core/input.js";
import { markdown, sarif } from "./core/reports.js";
import { InputError, obj, parseJSON, required } from "./core/validation.js";
const root = fileURLToPath(new URL("../", import.meta.url));
const publicDir = join(root, "public"),
  examples = join(root, "examples");
const assets = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/assets/app.js", ["assets/app.js", "text/javascript; charset=utf-8"]],
  ["/style.css", ["style.css", "text/css; charset=utf-8"]],
  ["/favicon.svg", ["favicon.svg", "image/svg+xml"]],
  ["/example.json", ["../examples/harbor.cdx.json", "application/json"]],
]);
function send(res: ServerResponse, code: number, body: unknown): void {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}
async function readBody(req: IncomingMessage): Promise<unknown> {
  if (!req.headers["content-type"]?.startsWith("application/json"))
    throw new InputError("Content-Type must be application/json.");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += Buffer.byteLength(chunk);
    if (size > 8 * 1024 * 1024) throw new InputError("Request exceeds 8 MiB.");
    chunks.push(Buffer.from(chunk));
  }
  return parseJSON(Buffer.concat(chunks).toString("utf8"));
}
export function createApp(options: { offline?: boolean } = {}) {
  let active = 0;
  const server = createServer(async (req, res) => {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=()",
    );
    const addr = server.address(),
      port = typeof addr === "object" && addr ? addr.port : 4317;
    const allowed = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
    if (!allowed.has(req.headers.host ?? "")) {
      send(res, 403, { error: "Only loopback Host headers are accepted." });
      return;
    }
    const origin = req.headers.origin;
    if (origin && ![...allowed].some((h) => origin === `http://${h}`)) {
      send(res, 403, { error: "Cross-origin requests are forbidden." });
      return;
    }
    try {
      const url = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
      if (req.method === "GET" && url.pathname === "/api/health") {
        send(res, 200, {
          status: "ok",
          version: "1.0.0",
          offline: !!options.offline,
        });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/demo") {
        const inventory = parseInventory(
          await readFile(join(examples, "harbor.cdx.json"), "utf8"),
        );
        const snapshot = validateSnapshot(
          parseJSON(
            await readFile(join(examples, "demo-evidence.json"), "utf8"),
          ),
        );
        const report = analyze(inventory, snapshot, {
          exposure: "internet",
          criticality: "critical",
        });
        send(res, 200, {
          report,
          snapshot,
          exports: { markdown: markdown(report), sarif: sarif(report) },
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/analyze") {
        if (req.headers["x-faultline-request"] !== "1") {
          send(res, 403, { error: "Missing same-origin request header." });
          return;
        }
        if (active >= 2) {
          send(res, 429, {
            error: "Two analyses are already running. Wait for one to finish.",
          });
          return;
        }
        active++;
        try {
          const body = obj(await readBody(req));
          if (typeof body.inventory !== "string")
            throw new InputError(
              "inventory must contain the SBOM as JSON text.",
            );
          const inventory = parseInventory(body.inventory);
          const context = validateContext(body.context);
          let snapshot;
          if (body.mode === "live") {
            if (options.offline)
              throw new InputError("This server was started in offline mode.");
            if (body.consent !== true)
              throw new InputError(
                "Confirm sharing package names/versions with OSV and CVE IDs with FIRST.",
              );
            snapshot = await collectEvidence(inventory);
          } else if (body.mode === "snapshot")
            snapshot = validateSnapshot(body.snapshot);
          else
            throw new InputError(
              "Select live intelligence or supply an evidence snapshot.",
            );
          const report = analyze(inventory, snapshot, context);
          send(res, 200, {
            report,
            snapshot,
            exports: { markdown: markdown(report), sarif: sarif(report) },
          });
        } finally {
          active--;
        }
        return;
      }
      const asset = assets.get(url.pathname);
      if (req.method === "GET" && asset) {
        const body = await readFile(join(publicDir, asset[0]!));
        res.writeHead(200, {
          "Content-Type": asset[1]!,
          "Content-Length": body.length,
        });
        res.end(body);
        return;
      }
      send(res, 404, { error: "Route not found." });
    } catch (e) {
      if (res.headersSent) {
        res.end();
        return;
      }
      send(res, e instanceof InputError ? 400 : 500, {
        error:
          e instanceof InputError
            ? e.message
            : "Analysis failed. Check input or try an evidence snapshot.",
      });
    }
  });
  server.requestTimeout = 120000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  return server;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT ?? 4317);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error("PORT must be between 1 and 65535.");
  const server = createApp({ offline: process.argv.includes("--offline") });
  server.listen(
    port,
    process.env.FAULTLINE_CONTAINER === "1" ? "0.0.0.0" : "127.0.0.1",
    () =>
      console.log(
        `Faultline → http://127.0.0.1:${port}\nLocal workspace · ${process.argv.includes("--offline") ? "network intelligence disabled" : "network intelligence requires explicit consent"}`,
      ),
  );
  server.on("error", (e) => {
    console.error(e.message);
    process.exitCode = 1;
  });
  const shutdown = (): void => {
    server.close();
    server.closeIdleConnections();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
