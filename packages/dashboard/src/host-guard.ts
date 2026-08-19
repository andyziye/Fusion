/**
 * Host-header validation (DNS-rebinding defense) shared by every dashboard entry surface.
 *
 * FNXC:HostGuard 2026-08-19-06:26:
 * A locally-bound dashboard was reachable from any web page the operator visited. The chain:
 * a malicious page publishes a short-TTL DNS record, rebinds it to 127.0.0.1, and the browser
 * then treats `http://attacker.example:4050` as SAME-ORIGIN — so CORS (which the server never
 * relaxes) is irrelevant, and every `/api/*` read plus the terminal WebSocket handshake is
 * reachable. With `--no-auth` (the `pnpm local` / localhost default) there is no bearer token in
 * the way, and `isOriginAllowed`'s same-host branch actively HELPED the attacker: it compared the
 * Origin against the request's own Host header, both of which the attacker controls, so they
 * always matched. Validating the Host header is the missing invariant.
 *
 * The rule, and why it does not break the shipped remote surfaces:
 *
 *  1. An IP-literal Host is always allowed. DNS rebinding needs a NAME — the browser reached an
 *     IP literal without consulting DNS, and an attacker page's origin is their domain, never the
 *     victim's IP. So `--host 0.0.0.0` LAN/mobile testing (Host: 10.0.0.5:4050) keeps working and
 *     gains nothing for an attacker.
 *  2. Loopback names (`localhost`) are allowed — the normal local browser origin.
 *  3. Anything else is a DNS name and must be explicitly allowlisted: `FUSION_ALLOWED_HOSTS`, or
 *     the `allowedHosts` option that createServer seeds from Remote Access settings (Tailscale
 *     hostname / Cloudflare ingress) so tunnels and reverse proxies keep working.
 *  4. A missing Host is allowed. HTTP/1.1 requires one and browsers always send it; native
 *     clients (our TUI, `curl` hook scripts) are gated by token/ticket instead. Rejecting here
 *     would break non-browser callers while adding nothing — a browser cannot omit it.
 *
 * This is deliberately an allowlist of NAMES, not a same-host comparison: the same-host shape is
 * what the rebinding attack defeats.
 */

/** Hosts that always denote this machine's own loopback interface. */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1", "0.0.0.0", "[::]", "::"]);

/**
 * Split `host` into its bare host and optional port.
 *
 * IPv6 arrives bracketed (`[::1]:4050`); a bare IPv6 Host (`::1`) has colons of its own, so a
 * naive `split(":")` would corrupt it. Only strip a trailing `:digits` when the remainder is not
 * an unbracketed multi-colon literal.
 */
function bareHost(host: string): string {
  const trimmed = host.trim().toLowerCase();
  if (trimmed.startsWith("[")) {
    const close = trimmed.indexOf("]");
    if (close === -1) return trimmed;
    return trimmed.slice(0, close + 1);
  }
  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon === -1) return trimmed;
  const maybePort = trimmed.slice(lastColon + 1);
  const head = trimmed.slice(0, lastColon);
  // A bare IPv6 literal still contains colons after removing the last group — leave it intact.
  if (head.includes(":")) return trimmed;
  if (maybePort.length > 0 && /^\d+$/.test(maybePort)) return head;
  return trimmed;
}

/** Loopback hosts the CLI-agent hook route accepts. Anything else is treated as cross-site. */
export function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  return LOOPBACK_HOSTS.has(bareHost(host));
}

/**
 * True when the bare host is an IP literal (v4 or bracketed/bare v6) rather than a DNS name.
 *
 * Only names are rebindable, so IP literals need no allowlist entry.
 */
export function isIpLiteralHost(host: string | undefined): boolean {
  if (!host) return false;
  const bare = bareHost(host);
  if (bare.startsWith("[") && bare.endsWith("]")) return true;
  // Bare IPv6 (no brackets) — any multi-colon form.
  if (bare.split(":").length > 2) return true;
  // IPv4 dotted quad. Reject 1.2.3.4.5 and 999.x by checking octet count and range.
  const octets = bare.split(".");
  if (octets.length !== 4) return false;
  return octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

/** Normalize an operator-supplied allowlist entry to the comparison form used by `isHostAllowed`. */
function normalizeAllowedHost(entry: string): string | undefined {
  const trimmed = entry.trim();
  if (trimmed.length === 0) return undefined;
  // Accept a pasted URL or bare host:port and reduce both to the bare host.
  const withoutScheme = trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const withoutPath = withoutScheme.split("/")[0] ?? withoutScheme;
  const bare = bareHost(withoutPath);
  return bare.length > 0 ? bare : undefined;
}

/**
 * Parse a comma/whitespace-separated allowlist.
 *
 * `*` disables name checking entirely — an explicit operator opt-out for exotic proxy setups,
 * recorded here rather than left as an undocumented "just turn the guard off" patch.
 */
export function parseAllowedHosts(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/[,\s]+/)
    .map(normalizeAllowedHost)
    .filter((entry): entry is string => entry !== undefined);
}

export interface HostCheckInput {
  host: string | undefined;
  /** Extra allowed hosts (bare host, `host:port`, or a full URL) from env/settings. */
  allowedHosts?: readonly string[];
}

/** True when this Host header may be served. See the module comment for the rule. */
export function isHostAllowed(input: HostCheckInput): boolean {
  const { host, allowedHosts } = input;
  // Non-browser callers (TUI, curl hook scripts) may omit Host; they are token/ticket gated.
  if (!host) return true;
  const bare = bareHost(host);
  if (bare.length === 0) return true;
  if (LOOPBACK_HOSTS.has(bare)) return true;
  if (isIpLiteralHost(bare)) return true;
  if (!allowedHosts || allowedHosts.length === 0) return false;
  for (const entry of allowedHosts) {
    if (entry === "*") return true;
    const normalized = normalizeAllowedHost(entry);
    if (normalized !== undefined && normalized === bare) return true;
  }
  return false;
}

/**
 * Allowed hosts contributed by the environment.
 *
 * Env vars are trusted configuration, so this needs no validation beyond normalization.
 */
export function allowedHostsFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  return parseAllowedHosts(env.FUSION_ALLOWED_HOSTS);
}

/**
 * Allowed hosts implied by Remote Access settings.
 *
 * FNXC:HostGuard 2026-08-19-06:26:
 * Tailscale and Cloudflare terminate at a PUBLIC name and may forward the original Host through
 * to this origin, so an enforced name allowlist would break a working tunnel. Seed the tunnel's
 * own hostname from settings rather than exempting tunnels wholesale. Both provider blocks are
 * read defensively because this runs against operator-authored settings.
 */
export function allowedHostsFromRemoteAccess(remoteAccess: unknown): string[] {
  if (typeof remoteAccess !== "object" || remoteAccess === null) return [];
  const providers = (remoteAccess as { providers?: unknown }).providers;
  if (typeof providers !== "object" || providers === null) return [];
  const hosts: string[] = [];
  const push = (value: unknown): void => {
    if (typeof value !== "string") return;
    const normalized = normalizeAllowedHost(value);
    if (normalized !== undefined) hosts.push(normalized);
  };
  const tailscale = (providers as { tailscale?: unknown }).tailscale;
  if (typeof tailscale === "object" && tailscale !== null) {
    push((tailscale as { hostname?: unknown }).hostname);
  }
  const cloudflare = (providers as { cloudflare?: unknown }).cloudflare;
  if (typeof cloudflare === "object" && cloudflare !== null) {
    push((cloudflare as { ingressUrl?: unknown }).ingressUrl);
    push((cloudflare as { tunnelName?: unknown }).tunnelName);
  }
  return hosts;
}

/*
FNXC:HostGuard 2026-08-19-06:26:
The middleware and allowlist wiring live here rather than in server.ts because that file is a
grandfathered line-count offender the project ratchet only lets shrink. Keeping the policy beside
the predicate also means the HTTP gate and the three WebSocket gates cannot drift.
*/

/** Minimal express-shaped types, so host-guard stays importable without an express dependency. */
interface HostGuardRequest {
  headers: { host?: string | undefined };
}
interface HostGuardResponse {
  status(code: number): { json(body: unknown): unknown };
}

export interface HostGuardSetupInput {
  /** Hosts supplied by the caller (`ServerOptions.allowedHosts`). */
  optionHosts?: readonly string[];
  /** Global-settings accessor; used to seed Remote Access hostnames. */
  loadRemoteAccess?: () => Promise<unknown>;
}

/**
 * Resolve the live per-server Host allowlist.
 *
 * Returns the mutable Set immediately (createServer is synchronous) and merges Remote Access
 * hostnames into it as soon as settings are readable. A tunnel's Host only arrives once the tunnel
 * is up, long after this settles; a settings read that throws leaves the env/option entries intact.
 */
export function resolveHostAllowlist(input: HostGuardSetupInput): Set<string> {
  const hosts = new Set<string>([...(input.optionHosts ?? []), ...allowedHostsFromEnv()]);
  if (input.loadRemoteAccess) {
    void (async () => {
      try {
        const settings = await input.loadRemoteAccess?.();
        const remoteAccess = (settings as { remoteAccess?: unknown } | undefined)?.remoteAccess;
        for (const host of allowedHostsFromRemoteAccess(remoteAccess)) {
          hosts.add(host);
        }
      } catch {
        // Settings unreadable (fresh store, migration in flight) — env/option allowlist still applies.
      }
    })();
  }
  return hosts;
}

/**
 * Express middleware rejecting unrecognized Host headers with `403 forbidden-host`.
 *
 * Mounted unconditionally and BEFORE the bearer-token middleware: the attack it stops is precisely
 * the no-token configuration, so gating it on auth would disable it where it is needed most.
 * `/api/health` is deliberately NOT exempt — a proxy deployment missing its allowlist entry should
 * fail loudly and uniformly rather than report healthy while every real route 403s.
 */
export function createHostGuardMiddleware(allowedHosts: Set<string>) {
  return function hostGuard(req: HostGuardRequest, res: HostGuardResponse, next: () => void): void {
    if (isHostAllowed({ host: req.headers.host, allowedHosts: [...allowedHosts] })) {
      return next();
    }
    res.status(403).json({ error: "forbidden-host" });
  };
}

/**
 * Read a server instance's resolved allowlist, falling back to option+env.
 *
 * The WebSocket setups are exported separately from createServer and may run against an app that
 * never went through it (tests, embedders), so an absent set must degrade to the static sources
 * rather than fail open.
 */
export function allowedHostsOrFallback(
  stored: Set<string> | undefined,
  optionHosts?: readonly string[],
): readonly string[] {
  if (stored) return [...stored];
  return [...(optionHosts ?? []), ...allowedHostsFromEnv()];
}
