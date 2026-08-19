/*
FNXC:HostGuard 2026-08-19-06:26:
Regression coverage for the DNS-rebinding invariant, asserted as an invariant across every surface
rather than only the reported repro (the cli-session WebSocket). The original hole: a locally-bound,
`--no-auth` dashboard was fully reachable from any page the operator visited, because the page could
rebind its own DNS name to 127.0.0.1 — the browser then treats the rebound origin as same-origin, so
CORS never applies, and `isOriginAllowed`'s same-host branch compared two attacker-controlled headers
against each other and passed.

Surfaces enumerated (all four must reject an unknown Host name):
  1. isHostAllowed          — the shared predicate
  2. isOriginAllowed        — /api/cli-sessions/ws gate (token + origin + ticket)
  3. /api/terminal/ws       — had NO host/origin check at all; token-only, skipped under --no-auth
  4. /api/ws (badge stream) — same shape as the terminal upgrade
  5. /api/* HTTP middleware — mounted unconditionally, independent of the bearer-token middleware
Surfaces 3-5 are exercised through the exported guard the server calls, so this file stays a unit
test; the wiring itself is asserted by the server/ws suites that construct real upgrades.

Both directions matter here, so the "keeps working" cases are as load-bearing as the rejections: an
over-tightened guard would silently break LAN/mobile testing and every tunnel.
*/

import { describe, expect, it } from "vitest";
import {
  allowedHostsFromEnv,
  allowedHostsFromRemoteAccess,
  isHostAllowed,
  isIpLiteralHost,
  isLoopbackHost,
  parseAllowedHosts,
} from "../host-guard.js";
import { isOriginAllowed } from "../cli-session-transport.js";

describe("isHostAllowed", () => {
  it("rejects an unknown DNS name — the rebinding vector", () => {
    expect(isHostAllowed({ host: "attacker.example" })).toBe(false);
    expect(isHostAllowed({ host: "attacker.example:4050" })).toBe(false);
    // A name that merely *contains* a loopback label must not pass.
    expect(isHostAllowed({ host: "localhost.attacker.example" })).toBe(false);
    expect(isHostAllowed({ host: "127.0.0.1.attacker.example" })).toBe(false);
  });

  it("allows loopback names and IP literals", () => {
    for (const host of ["localhost", "localhost:4050", "127.0.0.1", "127.0.0.1:4050", "[::1]:4050", "::1"]) {
      expect(isHostAllowed({ host })).toBe(true);
    }
  });

  it("allows LAN IP literals so --host 0.0.0.0 mobile testing keeps working", () => {
    // Rebinding needs a NAME; an IP-literal Host was reached without DNS, so it is not a vector.
    expect(isHostAllowed({ host: "10.10.10.180:4050" })).toBe(true);
    expect(isHostAllowed({ host: "192.168.1.24:4050" })).toBe(true);
    expect(isHostAllowed({ host: "[fe80::1]:4050" })).toBe(true);
  });

  it("allows an explicitly allowlisted DNS name so tunnels and reverse proxies keep working", () => {
    const allowedHosts = ["fusion.example.ts.net"];
    expect(isHostAllowed({ host: "fusion.example.ts.net", allowedHosts })).toBe(true);
    expect(isHostAllowed({ host: "fusion.example.ts.net:443", allowedHosts })).toBe(true);
    expect(isHostAllowed({ host: "other.example.ts.net", allowedHosts })).toBe(false);
  });

  it("treats an absent Host as allowed — native clients omit it and are token/ticket gated", () => {
    expect(isHostAllowed({ host: undefined })).toBe(true);
    expect(isHostAllowed({ host: "   " })).toBe(true);
  });

  it("honors the explicit * opt-out", () => {
    expect(isHostAllowed({ host: "anything.example", allowedHosts: ["*"] })).toBe(true);
  });

  it("is case-insensitive on the host name", () => {
    expect(isHostAllowed({ host: "LOCALHOST:4050" })).toBe(true);
    expect(isHostAllowed({ host: "Fusion.Example.Com", allowedHosts: ["fusion.example.com"] })).toBe(true);
  });
});

describe("isIpLiteralHost", () => {
  it("distinguishes IP literals from DNS names", () => {
    expect(isIpLiteralHost("10.0.0.1")).toBe(true);
    expect(isIpLiteralHost("[::1]")).toBe(true);
    expect(isIpLiteralHost("fe80::1")).toBe(true);
    expect(isIpLiteralHost("example.com")).toBe(false);
    // Not a dotted quad: octet count and range are both checked.
    expect(isIpLiteralHost("1.2.3.4.5")).toBe(false);
    expect(isIpLiteralHost("999.1.1.1")).toBe(false);
  });
});

describe("isLoopbackHost", () => {
  it("keeps the CLI-agent hook route's stricter loopback-only rule intact", () => {
    expect(isLoopbackHost("127.0.0.1:4050")).toBe(true);
    expect(isLoopbackHost("localhost")).toBe(true);
    expect(isLoopbackHost("[::1]:4050")).toBe(true);
    expect(isLoopbackHost(undefined)).toBe(false);
    // A LAN IP is allowed by the general guard but NOT by the hook route.
    expect(isLoopbackHost("10.10.10.180:4050")).toBe(false);
    expect(isLoopbackHost("attacker.example")).toBe(false);
  });
});

describe("allowlist sources", () => {
  it("parses comma and whitespace separated entries, URLs, and ports", () => {
    expect(parseAllowedHosts("a.example, b.example:8443 https://c.example/path")).toEqual([
      "a.example",
      "b.example",
      "c.example",
    ]);
    expect(parseAllowedHosts(undefined)).toEqual([]);
    expect(parseAllowedHosts("  ")).toEqual([]);
  });

  it("reads FUSION_ALLOWED_HOSTS", () => {
    expect(allowedHostsFromEnv({ FUSION_ALLOWED_HOSTS: "proxy.example" })).toEqual(["proxy.example"]);
    expect(allowedHostsFromEnv({})).toEqual([]);
  });

  it("seeds tunnel hostnames from Remote Access settings", () => {
    const hosts = allowedHostsFromRemoteAccess({
      providers: {
        tailscale: { hostname: "fusion-box" },
        cloudflare: { ingressUrl: "https://fusion.trycloudflare.com" },
      },
    });
    expect(hosts).toContain("fusion-box");
    expect(hosts).toContain("fusion.trycloudflare.com");
  });

  it("survives malformed or absent Remote Access settings", () => {
    // Runs against operator-authored settings, so every shape must be non-throwing.
    expect(allowedHostsFromRemoteAccess(undefined)).toEqual([]);
    expect(allowedHostsFromRemoteAccess(null)).toEqual([]);
    expect(allowedHostsFromRemoteAccess("nonsense")).toEqual([]);
    expect(allowedHostsFromRemoteAccess({ providers: null })).toEqual([]);
    expect(allowedHostsFromRemoteAccess({ providers: { tailscale: { hostname: 42 } } })).toEqual([]);
    expect(allowedHostsFromRemoteAccess({ providers: { cloudflare: { ingressUrl: "" } } })).toEqual([]);
  });
});

describe("isOriginAllowed", () => {
  it("no longer passes a rebound origin whose Origin matches an attacker-controlled Host", () => {
    /*
    This is the exact original defect. Both headers are the attacker's own name, so the same-host
    comparison agreed with itself and returned true; the browser considered the rebound origin
    same-origin, so no CORS check ever ran either.
    */
    expect(
      isOriginAllowed({
        origin: "http://attacker.example:4050",
        host: "attacker.example:4050",
      }),
    ).toBe(false);
  });

  it("rejects a rebound origin even when the caller supplies unrelated extra origins", () => {
    expect(
      isOriginAllowed({
        origin: "http://attacker.example:4050",
        host: "attacker.example:4050",
        extraAllowedOrigins: ["http://trusted.example"],
      }),
    ).toBe(false);
  });

  it("rejects an attacker Host even when the request carries no Origin at all", () => {
    // Host validation must not be reachable-around by simply omitting Origin.
    expect(isOriginAllowed({ origin: undefined, host: "attacker.example:4050" })).toBe(false);
  });

  it("still allows the legitimate same-origin localhost browser case", () => {
    expect(
      isOriginAllowed({
        origin: "http://localhost:4050",
        host: "localhost:4050",
        secFetchSite: "same-origin",
      }),
    ).toBe(true);
  });

  it("still allows the legitimate LAN IP case for mobile testing", () => {
    expect(
      isOriginAllowed({
        origin: "http://10.10.10.180:4050",
        host: "10.10.10.180:4050",
      }),
    ).toBe(true);
  });

  it("still allows an allowlisted tunnel host", () => {
    expect(
      isOriginAllowed({
        origin: "https://fusion.trycloudflare.com",
        host: "fusion.trycloudflare.com",
        allowedHosts: ["fusion.trycloudflare.com"],
      }),
    ).toBe(true);
  });

  it("still allows a native client with no Origin on a loopback Host", () => {
    expect(isOriginAllowed({ origin: undefined, host: "127.0.0.1:4050" })).toBe(true);
  });

  it("still rejects a cross-site browser request that omits Origin", () => {
    // Pre-existing behavior: a browser always sets Sec-Fetch-Site on cross-site requests.
    expect(
      isOriginAllowed({
        origin: undefined,
        host: "localhost:4050",
        secFetchSite: "cross-site",
      }),
    ).toBe(false);
  });

  it("still rejects a foreign Origin on an otherwise valid loopback Host", () => {
    // The CORS-style cross-origin case, independent of rebinding.
    expect(
      isOriginAllowed({
        origin: "http://evil.example",
        host: "localhost:4050",
      }),
    ).toBe(false);
  });

  it("still rejects a malformed Origin", () => {
    expect(isOriginAllowed({ origin: "not a url", host: "localhost:4050" })).toBe(false);
  });
});
