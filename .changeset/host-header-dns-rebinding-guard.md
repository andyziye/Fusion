---
"@runfusion/fusion": patch
---

summary: Block DNS-rebinding access to the dashboard, and bind `pnpm dev dashboard` to loopback.
category: security
dev: New `packages/dashboard/src/host-guard.ts` validates the `Host` header on `/api/*` and all three WS upgrades (`/api/terminal/ws`, `/api/ws`, `/api/cli-sessions/ws`); unknown DNS names get `403 {"error":"forbidden-host"}`. Loopback names, any IP literal, and an absent Host stay allowed, so `--host 0.0.0.0` LAN testing is unaffected. Allowlist other names via `FUSION_ALLOWED_HOSTS`, the `allowedHosts` server option, or Remote Access settings (Tailscale hostname / Cloudflare ingress are seeded automatically). `isOriginAllowed` now rejects an unrecognized Host before its same-host branch, which previously compared two attacker-controlled headers. `buildForwardedDevArgs` injects `--host 127.0.0.1` instead of `0.0.0.0`; pass `--host 0.0.0.0` explicitly for mobile testing.
