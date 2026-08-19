#!/usr/bin/env node
/**
 * Memory-aware development entrypoint for Fusion.
 * 
 * This script increases the Node.js heap size to prevent memory pressure
 * during the optional prebuild/start sequence, while preserving argument
 * pass-through for documented invocations like `pnpm dev dashboard`.
 * 
 * Cross-platform: Works on Windows, macOS, and Linux.
 */
import {
  buildForwardedDevArgs,
  buildDevNodeArgs,
  createDevWatchRestartCoordinator,
  getPrebuildCommand,
  parseDevWrapperArgs,
  readDevServerListeningPort,
  resolveDevTunnelPort,
  resolvePrebuildMode,
} from "./dev-with-memory-lib.mjs";
import { createDevSourceWatcher } from "./lib/dev-source-watch.mjs";
import { resolveDevTunnelAuth, startDevTunnel } from "./lib/dev-tunnel.mjs";

// Set increased heap size (8GB) to prevent OOM during initial build/start
const MEMORY_MB = process.env.FUSION_DEV_MEMORY_MB || "8192";

// Spawn the actual dev command with all arguments passed through
const { spawn } = await import("child_process");
const rawArgs = process.argv.slice(2);
let parsedArgs;
try {
  parsedArgs = parseDevWrapperArgs(rawArgs);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
const { inspectFlags, args, requestedPrebuild, watchSourceFromFlag, tunnel, tunnelPort } = parsedArgs;
let { watchSource } = parsedArgs;

// NODE_OPTIONS is shared with every spawned node process (build + run +
// agents). Heap size belongs here. Inspector flags do NOT — see comment above.
const nodeOptions = `--max-old-space-size=${MEMORY_MB} ${process.env.NODE_OPTIONS || ""}`.trim();
process.env.NODE_OPTIONS = nodeOptions;

// In dev we bind the dashboard to 127.0.0.1 — same as production. The injected host is only
// applied when starting the dashboard via `pnpm dev dashboard` and only if no --host was passed,
// so LAN/mobile testing stays available behind an explicit `--host 0.0.0.0`. See
// buildForwardedDevArgs in dev-with-memory-lib.mjs for why the LAN default was withdrawn.
const forwardedArgs = buildForwardedDevArgs(args);
if (watchSource && forwardedArgs[0] !== "dashboard") {
  if (watchSourceFromFlag) {
    console.error("[fusion:dev] --watch is supported for the dashboard engine process only");
    process.exit(1);
  }
  watchSource = false;
}
const prebuildMode = resolvePrebuildMode(requestedPrebuild, forwardedArgs);
const prebuildCommand = getPrebuildCommand(prebuildMode);

// Resolve absolute paths to tsx loader so they survive shell quoting.
// Use Node's resolver instead of hardcoding the pnpm version-specific path.
const { createRequire } = await import("node:module");
const path = await import("node:path");
const require = createRequire(import.meta.url);
const tsxPkgJson = require.resolve("tsx/package.json");
const tsxDir = path.dirname(tsxPkgJson);
const PRELOAD = path.join(tsxDir, "dist", "preflight.cjs");
const LOADER = path.join(tsxDir, "dist", "loader.mjs");
const ENTRY = path.resolve(process.cwd(), "packages/cli/src/bin.ts");

// Spawn node directly (no shell) so the inspector attaches to the real app
// process and there's no parent/child wrapper consuming --inspect.
// Inspector flags are CLI args here so they apply only to this process and
// don't propagate to grandchildren via NODE_OPTIONS.
/*
FNXC:SystemPanel 2026-07-12-10:45:
This wrapper is the supervising parent for `pnpm dev` / `pnpm start`, so it is
where the dashboard System panel's "Restart"/"Rebuild & restart" actions land:
the child exits with FUSION_RESTART_EXIT_CODE (86 — keep in sync with
packages/core/src/process-supervisor.ts) and we respawn the same command
immediately, keeping the same terminal/TTY so the TUI comes back seamlessly.
FUSION_RESTART_SUPERVISED=1 tells the child a respawning parent exists, which
is what makes the dashboard advertise restart support. Any other exit code
propagates unchanged (no crash-restart loop here — `--supervise` owns that).
*/
const RESTART_EXIT_CODE = 86;
let appChild;
let devTunnel;
let sourceWatcher;
const watchRestart = createDevWatchRestartCoordinator();

function ensureSourceWatcher() {
  if (!watchSource || sourceWatcher) return;
  sourceWatcher = createDevSourceWatcher({
    rootDir: process.cwd(),
    onRestart: (paths) => watchRestart.request(paths),
  });
  console.log(`[fusion:dev] source watch active (${sourceWatcher.watchedPaths.join(", ")})`);
}

/*
FNXC:DevTunnel 2026-08-19-02:05:
Which port to tunnel is NOT knowable up front. `resolveDevTunnelPort` returns the port the dev
server is asked for, but an occupied port makes the dashboard rebind to an ephemeral one — so with a
normal Fusion already holding 4040, the tunnel pointed at THAT instance and served the wrong app
under a dev-looking URL. Wait for the child's listening report and tunnel the port it actually got.

An explicit `--tunnel=PORT` names a target the operator chose (a Vite server the dev child knows
nothing about), so it is used immediately and never waits. If the report never arrives the tunnel
still comes up on the configured port, since a mis-targeted preview beats no preview at all.
*/
const DEV_SERVER_PORT_REPORT_TIMEOUT_MS = 60_000;
let reportDevServerPort;
const devServerPortReport = new Promise((resolve) => { reportDevServerPort = resolve; });

async function resolveTunnelTargetPort() {
  if (tunnelPort) return { port: tunnelPort, source: "explicit" };

  const configured = resolveDevTunnelPort(undefined);
  const timeout = new Promise((resolve) => {
    setTimeout(() => resolve(null), DEV_SERVER_PORT_REPORT_TIMEOUT_MS).unref?.();
  });
  const reported = await Promise.race([devServerPortReport, timeout]);

  if (reported == null) {
    console.warn(`[fusion:dev] dev server never reported its port — tunnelling ${configured}, which may not be it`);
    return { port: configured, source: "assumed" };
  }
  if (reported !== configured) {
    console.log(`[fusion:dev] dev server bound ${reported} (not ${configured}) — tunnelling ${reported}`);
  }
  return { port: reported, source: "reported" };
}

async function openDevTunnel() {
  const { port, source } = await resolveTunnelTargetPort();
  /*
  FNXC:DevTunnel 2026-08-19-02:05:
  A port the CHILD reported is the dev dashboard by definition, whatever number it landed on — so it
  is its own dashboardPort. Treating it as "some other port" would drop the token from the banner
  precisely in the ephemeral-rebind case this fix exists for. An explicit --tunnel=PORT names an
  arbitrary target, so that one is still compared against the configured dashboard port.
  */
  const dashboardPort = source === "explicit" ? resolveDevTunnelPort(undefined) : port;
  /*
  FNXC:DevTunnel 2026-08-19-01:18:
  Resolved at print time (not at parse time) so the token the dev child mints on a first
  authenticated run is already on disk by the time the banner needs it.
  */
  const auth = resolveDevTunnelAuth({ port, dashboardPort, args: forwardedArgs });
  devTunnel = await startDevTunnel({ port, auth });
}

function runApp(extraArgs) {
  const tsx = spawn(process.execPath, buildDevNodeArgs({
    inspectFlags,
    preload: PRELOAD,
    loader: LOADER,
    entry: ENTRY,
    args: extraArgs,
  }), {
    // FNXC:DevTunnel 2026-08-19-02:05: the tunnel needs the child's IPC channel too, to learn the
    // port it actually bound — not only watch mode.
    stdio: (watchSource || tunnel) ? ["inherit", "inherit", "inherit", "ipc"] : "inherit",
    // FNXC:SystemPanel 2026-07-25-10:05: stamp the supervisor pid alongside the
    // flag so the child can tell a real supervising parent from an inherited
    // copy of the variable (see hasLiveSupervisingParent in commands/dashboard.ts).
    env: {
      ...process.env,
      FUSION_RESTART_SUPERVISED: "1",
      FUSION_SUPERVISOR_PID: String(process.pid),
      ...(watchSource ? { FUSION_DEV_WATCH: "1" } : {}),
    },
  });
  appChild = tsx;
  /*
  FNXC:DevTunnel 2026-08-18-23:40:
  Started AFTER the dev child so the tunnel points at a port something is actually about to serve,
  and torn down with it. Deliberately fire-and-forget: a tunnel that fails to come up logs and is
  skipped rather than taking the dev loop down with it — losing a preview URL must never cost the
  operator their dev server. Restarts (watch mode) reuse the existing tunnel, since the port is
  unchanged and a fresh quick tunnel would hand out a different hostname every reload.
  */
  if (tunnel && !devTunnel) {
    devTunnel = { url: null, stop: () => {} };
    void openDevTunnel().catch((error) => {
      console.error(`[fusion:dev] tunnel error: ${error instanceof Error ? error.message : String(error)}`);
    });
  }
  watchRestart.attach(tsx);
  tsx.on("message", (message) => {
    const listeningPort = readDevServerListeningPort(message);
    if (listeningPort) reportDevServerPort(listeningPort);
    watchRestart.onMessage(message);
  });
  ensureSourceWatcher();
  tsx.on("close", (c) => {
    const sourceRestart = watchRestart.detach(tsx);
    if (appChild === tsx) appChild = undefined;
    if (c === RESTART_EXIT_CODE) {
      console.log("[fusion:dev] restart requested — restarting…");
      if (sourceRestart && prebuildCommand) {
        runPrebuild(() => runApp(extraArgs));
      } else {
        runApp(extraArgs);
      }
      return;
    }
    devTunnel?.stop?.();
    process.exit(c ?? 1);
  });
}

function runPrebuild(onSuccess) {
  console.log(`[fusion] Running ${prebuildCommand.label} (${prebuildMode}) before source startup...`);
  const build = spawn(prebuildCommand.command, prebuildCommand.args, { stdio: "inherit", shell: true });
  build.on("close", (code) => {
    if (code !== 0) process.exit(code ?? 1);
    onSuccess();
  });
}

async function warnIfSourceVersionBehind() {
  if (process.env.FUSION_SKIP_STARTUP_UPDATE_PREFLIGHT === "1") {
    return;
  }

  let currentVersion;
  try {
    const { readFile } = await import("node:fs/promises");
    const pkg = JSON.parse(await readFile(path.resolve(process.cwd(), "packages/cli/package.json"), "utf8"));
    currentVersion = typeof pkg.version === "string" ? pkg.version : undefined;
  } catch {
    return;
  }

  if (!currentVersion) return;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1_500);
    let payload;
    try {
      const response = await fetch("https://registry.npmjs.org/@runfusion%2Ffusion", {
        signal: controller.signal,
      });
      payload = await response.json();
    } finally {
      clearTimeout(timeout);
    }
    const latestVersion = payload?.["dist-tags"]?.latest;
    if (typeof latestVersion !== "string") return;

    const currentParts = currentVersion.split(".").map((part) => Number.parseInt(part, 10) || 0);
    const latestParts = latestVersion.split(".").map((part) => Number.parseInt(part, 10) || 0);
    let latestIsNewer = false;
    for (let i = 0; i < Math.max(currentParts.length, latestParts.length, 3); i += 1) {
      const latest = latestParts[i] ?? 0;
      const current = currentParts[i] ?? 0;
      if (latest > current) {
        latestIsNewer = true;
        break;
      }
      if (latest < current) {
        break;
      }
    }

    if (latestIsNewer) {
      console.warn(
        `\n[fusion] This source checkout is v${currentVersion}, but npm latest is v${latestVersion}. ` +
        "If you meant to run the latest Fusion, pull/switch branches before startup.\n",
      );
    }
  } catch {
    // Best-effort only. Startup must not depend on the registry.
  }
}

await warnIfSourceVersionBehind();

// FNXC:DevWorkflow 2026-06-18-16:50:
// FN-6638 stale-dist guard. Warn (loudly, best-effort) when built dist/ is older
// than src/ so a never-rebuilt/never-restarted process does not silently run
// phantom-old code. When a prebuild is about to run it will refresh dist, so the
// check is informational there; for --prebuild none / dist-resolving consumers
// it is the safety net. Never let the check break startup.
async function warnIfDistStale() {
  if (process.env.FUSION_SKIP_DIST_FRESHNESS_CHECK === "1") return;
  try {
    const { computeDistStaleness, formatDistStalenessWarning } = await import("./lib/dist-freshness.mjs");
    const warning = formatDistStalenessWarning(computeDistStaleness({ rootDir: process.cwd() }));
    if (warning) console.warn(warning);
  } catch {
    // Best-effort only. Startup must not depend on the freshness check.
  }
}

await warnIfDistStale();

if (!prebuildCommand) {
  runApp(forwardedArgs);
} else {
  runPrebuild(() => runApp(forwardedArgs));
}
