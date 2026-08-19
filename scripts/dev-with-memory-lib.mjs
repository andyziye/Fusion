export function buildDevNodeArgs({
  inspectFlags = [],
  preload,
  loader,
  entry,
  args = [],
}) {
  return [
    ...inspectFlags,
    "--conditions=source",
    "--require",
    preload,
    "--import",
    `file://${loader}`,
    entry,
    ...args,
  ];
}

export function createDevWatchRestartCoordinator({ log = console.log, warn = console.warn } = {}) {
  let child;
  let armed = false;
  let queued = false;
  let pendingPaths = [];

  const requeuePaths = (changedPaths) => {
    pendingPaths = [...new Set([...pendingPaths, ...changedPaths])];
  };

  const sendRestart = (changedPaths) => {
    if (!child?.connected) {
      requeuePaths(changedPaths);
      warn("[fusion:dev] source restart deferred; the engine child is not connected");
      return;
    }
    const preview = changedPaths.slice(0, 3).join(", ");
    const remainder = Math.max(0, changedPaths.length - 3);
    log(`[fusion:dev] source changed (${preview}${remainder > 0 ? ` +${remainder} more` : ""}) — restart queued…`);
    queued = true;
    try {
      child.send({ type: "fusion:dev-source-changed" }, (error) => {
        if (!error) return;
        queued = false;
        requeuePaths(changedPaths);
        warn(`[fusion:dev] source restart message failed: ${error.message}`);
      });
    } catch (error) {
      queued = false;
      requeuePaths(changedPaths);
      warn(`[fusion:dev] source restart message failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  return {
    attach(nextChild) {
      child = nextChild;
      armed = false;
      queued = false;
    },
    request(changedPaths) {
      if (queued) return;
      if (!armed) {
        pendingPaths = [...new Set([...pendingPaths, ...changedPaths])];
        log("[fusion:dev] source changed while the engine child is starting — restart will queue when watch is armed");
        return;
      }
      if (!child?.connected) {
        requeuePaths(changedPaths);
        warn("[fusion:dev] source restart deferred; the engine child is not connected");
        return;
      }
      const paths = [...new Set([...pendingPaths, ...changedPaths])];
      pendingPaths = [];
      sendRestart(paths);
    },
    onMessage(message) {
      if (!message || typeof message !== "object" || message.type !== "fusion:dev-source-restart-armed") return;
      armed = true;
      if (pendingPaths.length === 0) return;
      const paths = pendingPaths;
      pendingPaths = [];
      sendRestart(paths);
    },
    detach(nextChild) {
      if (child !== nextChild) return false;
      const sourceRestart = queued;
      child = undefined;
      armed = false;
      return sourceRestart;
    },
  };
}

const VALID_PREBUILD_MODES = new Set(["auto", "none", "client", "full"]);

export function normalizePrebuildMode(value) {
  const mode = value === undefined || value === null ? "auto" : String(value).toLowerCase();
  if (mode === "" || !VALID_PREBUILD_MODES.has(mode)) {
    throw new Error(`Invalid prebuild mode "${value}". Expected one of: auto, none, client, full.`);
  }
  return mode;
}

export function hasHostOverride(args) {
  return args.includes("--host") || args.some((arg) => arg.startsWith("--host="));
}

export function buildForwardedDevArgs(args) {
  /*
  FNXC:DevWorkflow 2026-07-12-10:20:
  `pnpm dev` and `pnpm start` with no command must behave exactly like
  `pnpm dev dashboard` (client prebuild + host injection), not fall through
  to the CLI's bare default. Normalize empty/flag-only invocations to an
  explicit "dashboard" command so every downstream decision (prebuild mode,
  host injection) sees the same shape.

  FNXC:DevWorkflow 2026-08-19-06:26:
  The injected host is now LOOPBACK, not 0.0.0.0. `pnpm dev dashboard` used to bind every
  interface so phones and other LAN machines could reach it, but on an untrusted network (office,
  cafe, conference wifi) that publishes a dashboard which — with auth off — exposes an in-browser
  terminal to the whole subnet. Reaching a dev box from a phone is occasional; leaking a shell is
  not an acceptable default for it. `hasHostOverride` still wins, so deliberate LAN testing is one
  explicit flag away: `pnpm dev dashboard --host 0.0.0.0`.
  */
  const hasCommand = args.length > 0 && !String(args[0]).startsWith("-");
  const normalized = hasCommand ? args : ["dashboard", ...args];
  const needsDevHostInjection = normalized[0] === "dashboard" && !hasHostOverride(normalized);
  return needsDevHostInjection ? [...normalized, "--host", "127.0.0.1"] : normalized;
}

export function parseDevWrapperArgs(rawArgs, env = process.env) {
  const inspectFlags = [];
  const args = [];
  let requestedPrebuild = env.FUSION_DEV_PREBUILD ?? "auto";
  let watchSource = env.FUSION_DEV_WATCH === "1";
  let watchSourceFromFlag = false;
  /*
  FNXC:DevTunnel 2026-08-18-23:40:
  `--tunnel` exposes the dev server through a Cloudflare quick tunnel, for working inside a remote
  Fusion (container or shared box) and needing to view the dev server from your own browser.
  `--tunnel=PORT` targets a port other than the dashboard's (e.g. a Vite server on 5173).
  */
  let tunnel = env.FUSION_DEV_TUNNEL === "1";
  let tunnelPort = env.FUSION_DEV_TUNNEL_PORT ? Number(env.FUSION_DEV_TUNNEL_PORT) : undefined;

  for (let i = 0; i < rawArgs.length; i += 1) {
    const arg = rawArgs[i];
    if (arg === "--inspect" || arg === "--inspect-brk" || arg.startsWith("--inspect=") || arg.startsWith("--inspect-brk=")) {
      inspectFlags.push(arg);
      continue;
    }

    if (arg === "--prebuild") {
      const value = rawArgs[i + 1];
      if (!value) {
        throw new Error("Missing value for --prebuild. Expected one of: auto, none, client, full.");
      }
      requestedPrebuild = value;
      i += 1;
      continue;
    }

    if (arg.startsWith("--prebuild=")) {
      requestedPrebuild = arg.slice("--prebuild=".length);
      continue;
    }

    if (arg === "--skip-build") {
      requestedPrebuild = "none";
      continue;
    }

    if (arg === "--watch") {
      watchSource = true;
      watchSourceFromFlag = true;
      continue;
    }

    if (arg === "--tunnel") {
      tunnel = true;
      const next = rawArgs[i + 1];
      // Accept `--tunnel 5173` only when the next token is a port, so `--tunnel dashboard` still
      // forwards `dashboard` to the dev command instead of swallowing it.
      if (next && /^\d+$/.test(next)) {
        tunnelPort = Number(next);
        i += 1;
      }
      continue;
    }

    if (arg.startsWith("--tunnel=")) {
      tunnel = true;
      const value = arg.slice("--tunnel=".length);
      if (!/^\d+$/.test(value)) {
        throw new Error(`Invalid value for --tunnel: ${value}. Expected a port number.`);
      }
      tunnelPort = Number(value);
      continue;
    }

    args.push(arg);
  }

  return {
    inspectFlags,
    args,
    requestedPrebuild: normalizePrebuildMode(requestedPrebuild),
    watchSource,
    watchSourceFromFlag,
    tunnel,
    tunnelPort,
  };
}

/*
FNXC:DevTunnel 2026-08-19-02:05:
Mirrors DEV_SERVER_LISTENING_MESSAGE in packages/cli/src/commands/dev-source-restart.ts. The literal
is duplicated rather than imported because this wrapper is plain JS that must not load the TS build.
*/
export const DEV_SERVER_LISTENING_MESSAGE = "fusion:dev-server-listening";

/** Port from a dev child's listening report, or null for any other message. */
export function readDevServerListeningPort(message) {
  if (!message || typeof message !== "object") return null;
  if (message.type !== DEV_SERVER_LISTENING_MESSAGE) return null;
  const port = Number(message.port);
  return Number.isInteger(port) && port > 0 ? port : null;
}

/**
 * Port the tunnel should point at.
 *
 * FNXC:DevTunnel 2026-08-18-23:40: defaults to the dashboard's port, because `pnpm dev` with no
 * target starts the dashboard. An explicit `--tunnel=PORT` wins so a Vite dev server (or anything
 * else the operator started) can be exposed instead.
 *
 * FNXC:DevTunnel 2026-08-19-02:05: this is the port the dev server is ASKED for, which is only a
 * guess — an occupied port makes it rebind to an ephemeral one. Without an explicit --tunnel=PORT
 * the caller must prefer the port the child reports over this value; see
 * readDevServerListeningPort.
 */
export function resolveDevTunnelPort(tunnelPort, env = process.env) {
  if (tunnelPort) return tunnelPort;
  const fromEnv = Number(env.PORT);
  return Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : 4040;
}

export function resolvePrebuildMode(requestedPrebuild, forwardedArgs) {
  const mode = normalizePrebuildMode(requestedPrebuild);
  if (mode !== "auto") {
    return mode;
  }

  const command = forwardedArgs[0] ?? "dashboard";
  return command === "dashboard" ? "client" : "none";
}

export function getPrebuildCommand(mode) {
  switch (normalizePrebuildMode(mode)) {
    case "full":
      return { command: "pnpm", args: ["build"], label: "workspace build" };
    case "client":
      /*
      FNXC:DevWorkflow 2026-06-18-16:40:
      FN-6638/stale-dist: `pnpm dev dashboard` must rebuild @fusion/core and
      @fusion/engine alongside the dashboard UI, not only the client bundle.
      Although the CLI runs under `--conditions=source` (engine/core resolve to
      src), the running process and any dist-resolving consumer (plugins,
      sub-imports, a later non-dev `fn`/`pnpm local`) load built dist. Leaving
      engine/core dist stale is exactly how landed fixes (FN-6644/6647/6648,
      etc.) silently failed to run for ~2 days.

      FNXC:DevWorkflow 2026-07-10-15:40:
      FN-7779/stale-plugin-dist: the app-package build alone left plugin dist/
      stale — a source-only plugin fix (the Grok CLI-flag fix behind "messages
      aren't sending") never took effect until a manual rebuild. The client
      prebuild is now an orchestrator (scripts/dev-prebuild-client.mjs) that
      first runs the fast core → engine → dashboard build (dependency order;
      dashboard `build` also runs the vite client bundle + server tsc) and then
      incrementally rebuilds ONLY changed plugins via the content-hash skip
      cache. A single node command keeps the spawn contract cross-platform.
      */
      return {
        command: "node",
        args: ["scripts/dev-prebuild-client.mjs"],
        label: "core + engine + dashboard + changed plugins build",
      };
    case "none":
    case "auto":
      return null;
  }
}
