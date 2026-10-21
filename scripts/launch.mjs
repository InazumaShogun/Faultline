import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

async function smallText(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 8192) throw new Error("Not a Faultline startup response.");
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    await reader.cancel().catch(() => {});
  }
}

/** Reuse a verified Faultline instance, including the original v1.0 server. */
export async function isFaultline(url) {
  try {
    const health = await fetch(new URL("/api/health", url), {
      signal: AbortSignal.timeout(1500),
      redirect: "error",
    });
    if (!health.ok) return false;
    const data = JSON.parse(await smallText(health));
    if (data.status !== "ok" || typeof data.version !== "string") return false;
    const page = await fetch(url, {
      signal: AbortSignal.timeout(1500),
      redirect: "error",
    });
    return page.ok && /<title>Faultline\b/.test(await smallText(page));
  } catch {
    return false;
  }
}

/** Bind atomically; never stop or replace another service occupying a port. */
export async function listenAvailable(createServer, preferred, allowFallback) {
  const attempts = allowFallback ? 11 : 1;
  for (let i = 0; i < attempts && preferred + i <= 65535; i++) {
    const server = createServer();
    try {
      await new Promise((resolve, reject) => {
        const fail = (error) => reject(error);
        server.once("error", fail);
        server.listen(preferred + i, "127.0.0.1", () => {
          server.off("error", fail);
          resolve();
        });
      });
      return { server, port: preferred + i };
    } catch (error) {
      if (error.code !== "EADDRINUSE") throw error;
      if (!allowFallback)
        throw new Error(
          `Port ${preferred} is occupied by another application. Choose a different PORT or remove the PORT setting.`,
        );
    }
  }
  throw new Error(
    "No free local port was found. Set PORT to an available port and try again.",
  );
}

function openBrowser(url) {
  if (process.env.FAULTLINE_NO_BROWSER === "1") return;
  const command =
    process.platform === "win32"
      ? "cmd.exe"
      : process.platform === "darwin"
        ? "open"
        : "xdg-open";
  const args =
    process.platform === "win32" ? ["/d", "/c", "start", "", url] : [url];
  const child = spawn(command, args, { windowsHide: true, stdio: "ignore" });
  child.on("error", () => console.log(`Open ${url} manually in your browser.`));
}

export async function main() {
  const root = fileURLToPath(new URL("../", import.meta.url));
  process.chdir(root);
  const preferred = Number(process.env.PORT ?? 4317);
  if (!Number.isInteger(preferred) || preferred < 1 || preferred > 65535)
    throw new Error("PORT must be between 1 and 65535.");
  const preferredURL = `http://127.0.0.1:${preferred}/`;
  if (await isFaultline(preferredURL)) {
    console.log(`Faultline is already running. Opening ${preferredURL}`);
    openBrowser(preferredURL);
    return;
  }
  await access(new URL("../dist/public/assets/app.js", import.meta.url)).catch(
    () => {
      throw new Error(
        "The build is incomplete. Extract the full prebuilt package or run npm run build.",
      );
    },
  );
  const { createApp } = await import("../dist/src/server.js");
  const { server, port } = await listenAvailable(
    () => createApp(),
    preferred,
    process.env.PORT === undefined,
  );
  const url = `http://127.0.0.1:${port}/`;
  if (port !== preferred)
    console.log(
      `Port ${preferred} is busy with another application; using ${port}.`,
    );
  console.log(
    `Faultline is ready: ${url}\nKeep this window open. Press Ctrl+C to stop.\nLive intelligence still requires your explicit consent.`,
  );
  server.on("error", (error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
  const shutdown = () => {
    server.close();
    server.closeIdleConnections();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  openBrowser(url);
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error) => {
    console.error(`Faultline: ${error.message}`);
    process.exitCode = 1;
  });
}
