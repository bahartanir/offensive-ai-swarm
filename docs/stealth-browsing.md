# Stealth Browsing (camofox-browser)

Reference doc for all hunting agents. **Read this before testing any target that returns Cloudflare / Akamai / Google / DataDome / PerimeterX bot-detection challenges.**

## What it is

`camofox-browser` is a local REST server on `http://localhost:9377` that wraps [Camoufox](https://camoufox.com), a Firefox fork that patches fingerprints at the C++ implementation level. `navigator.webdriver`, `navigator.hardwareConcurrency`, WebGL vendor/renderer, AudioContext, screen geometry, and WebRTC are all spoofed *before* JavaScript can read them — not via JS shims that `Function.prototype.toString` can detect.

Server source: `/root/tools/camofox-browser` (npm project, not modified by the framework).
Camoufox binary cache: `/root/.cache/camoufox/`.

## When to reach for it

Use camofox-browser when any of the following are true:

1. `httpx`/`curl`/`nuclei` returns 403 / 429 / a CF interstitial for an in-scope host.
2. Testing a client-side bug class (XSS reflected/stored/DOM, prototype pollution, postMessage, open redirect) where you need a real browser render to prove execution.
3. Capturing screenshot evidence for a report and vanilla chromium / headless Chrome shows the challenge page instead of the vulnerable page.
4. The target is GeoIP-gated and you need locale/timezone matching via a residential proxy.
5. Verifying stored XSS fires in a victim context when the victim's browser profile would hit CF challenges.

Do **not** use camofox-browser when:
- The target returns clean responses to `curl` (vanilla HTTP is faster; don't burn browser resources).
- You need to inspect/modify the wire protocol — use the `browser-agent` (Burp MCP) instead.
- The bug is purely server-side (SSRF, SQLi, IDOR via direct API calls) — `curl` is the right tool.

## How it differs from `browser-agent` (Burp MCP)

| Concern | `browser-agent` (Burp MCP) | `browser-stealth-agent` (camofox) |
|---|---|---|
| Primary purpose | Traffic inspection, modification, replay | Stealth rendering that survives bot detection |
| Engine | Chrome via Claude-in-Chrome MCP | Camoufox (patched Firefox) via local REST |
| Fingerprint defense | None — trivially fingerprinted | C++-level spoof, invisible to JS |
| HTTP mutation | Via Burp proxy | Not supported |
| Network visibility | Full proxy log via `burp.get_proxy_history` | Limited — accessibility tree + screenshots |
| When to pick it | Auth logic, HTTP smuggling, request crafting, OOB via Collaborator | CF/Akamai-protected pages, client-side bug verification, GeoIP-gated recon |

Both agents can run concurrently. The Opus orchestrator picks based on the vuln class and target characteristics.

## Lifecycle

Use `tools/camofox_ctl.sh` — never shell-juggle `nohup`/`pkill` directly.

```bash
./tools/camofox_ctl.sh start   # launches server, waits for /health up to 20s
./tools/camofox_ctl.sh status  # prints running pid + health JSON
./tools/camofox_ctl.sh logs    # tails last 100 lines of /tmp/camofox.log
./tools/camofox_ctl.sh stop    # kills server, removes pidfile
```

Env-var overrides (set before `start`):
- `CAMOFOX_DIR` — path to the npm project (default `/root/tools/camofox-browser`)
- `CAMOFOX_PID_FILE` — pidfile path (default `/tmp/camofox.pid`)
- `CAMOFOX_LOG_FILE` — log path (default `/tmp/camofox.log`)
- `CAMOFOX_HEALTH_URL` — health endpoint (default `http://localhost:9377/health`)

## REST API cheat sheet

All endpoints accept `Content-Type: application/json`. Sessions are scoped by `userId`. A `sessionKey` groups related tabs (e.g. one auth session across multiple tabs).

### Health
```bash
curl -sS http://localhost:9377/health | jq .
```
Returns: `{"ok": true, "engine": "camoufox", "browserConnected": true, "browserRunning": true, "activeTabs": N, "activeSessions": N, "consecutiveFailures": 0}`

### Create tab (and navigate)
```bash
TAB=$(curl -sS -X POST http://localhost:9377/tabs \
  -H 'Content-Type: application/json' \
  -d '{"userId":"hunter","sessionKey":"target1","url":"https://target.example.com"}' \
  | jq -r .tabId)
```

### Navigate existing tab
```bash
curl -sS -X POST "http://localhost:9377/tabs/$TAB/navigate" \
  -H 'Content-Type: application/json' \
  -d '{"userId":"hunter","url":"https://target.example.com/account"}'
```

### Snapshot (accessibility tree + element refs)
```bash
curl -sS "http://localhost:9377/tabs/$TAB/snapshot?userId=hunter" | jq -r .snapshot
```
Snapshots are ~90% smaller than raw HTML and use stable refs `e1`, `e2`, ... for clickable/typeable elements.

### Click by ref
```bash
curl -sS -X POST "http://localhost:9377/tabs/$TAB/click" \
  -H 'Content-Type: application/json' \
  -d '{"userId":"hunter","ref":"e1"}'
```

### Type into ref
```bash
curl -sS -X POST "http://localhost:9377/tabs/$TAB/type" \
  -H 'Content-Type: application/json' \
  -d '{"userId":"hunter","ref":"e2","text":"attacker@example.com"}'
```

### Wait for page to settle
```bash
curl -sS -X POST "http://localhost:9377/tabs/$TAB/wait" \
  -H 'Content-Type: application/json' \
  -d '{"userId":"hunter","timeout":10000,"waitForNetwork":true}'
```
Use this after clicks/navigations that trigger SPA hydration or async network activity.

### Screenshot (binary PNG)
```bash
curl -sS "http://localhost:9377/tabs/$TAB/screenshot?userId=hunter&fullPage=true" \
  -o evidence/step_1_target.png
```

### Cookie import (authenticated browsing)
The endpoint takes an array of Playwright-shaped cookie objects. Required fields per cookie: `name`, `value`, `domain`. Optional: `path`, `expires`, `httpOnly`, `secure`, `sameSite`. Max 500 cookies per request.

Auth: set `CAMOFOX_API_KEY` before `start` and pass it as `Authorization: Bearer ...`. Without the API key the endpoint still accepts loopback requests when `NODE_ENV != production` (see `server.js:185-192`); in production or non-loopback, it returns 403.

```bash
# 1. Generate a key once and persist it:
export CAMOFOX_API_KEY="$(openssl rand -hex 32)"
# 2. Restart the server so it picks up the key:
./tools/camofox_ctl.sh stop && ./tools/camofox_ctl.sh start
# 3. Import a cookie array (userId must match the session you'll use):
curl -sS -X POST "http://localhost:9377/sessions/hunter/cookies" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CAMOFOX_API_KEY" \
  -d '{
    "cookies": [
      {
        "name": "session",
        "value": "abc123...",
        "domain": ".target.example.com",
        "path": "/",
        "httpOnly": true,
        "secure": true,
        "sameSite": "Lax"
      }
    ]
  }'
```

To convert a Netscape-format `cookies.txt` file to this JSON shape, parse it with `awk` / `jq` or a one-liner Python script — the server does not accept the raw Netscape format.

### Close tab (cleanup)
```bash
curl -sS -X DELETE "http://localhost:9377/tabs/$TAB?userId=hunter"
```

## Residential proxy + GeoIP

For BB engagements against targets with IP reputation scoring, route camofox through a residential proxy. The server reads proxy config directly from `process.env` at launch (via `lib/config.js`); `tools/camofox_ctl.sh` just inherits your environment, so export these BEFORE calling `start`:

```bash
export PROXY_STRATEGY="rotating"         # "rotating" | "sticky" | "static"
export PROXY_PROVIDER="decodo"           # or your provider name
export PROXY_HOST="proxy.provider.com"
export PROXY_PORT="8080"
export PROXY_USERNAME="user"
export PROXY_PASSWORD="pass"
export PROXY_COUNTRY="US"                # ISO country code — enables GeoIP locale/timezone match
./tools/camofox_ctl.sh stop && ./tools/camofox_ctl.sh start
```

Optional narrowing: `PROXY_STATE`, `PROXY_CITY`, `PROXY_ZIP`. For backconnect providers: `PROXY_BACKCONNECT_HOST` / `PROXY_BACKCONNECT_PORT` (default 7000). Session lifetime: `PROXY_SESSION_DURATION_MINUTES` (default 10).

Verify the proxy took effect via `/health`:
```bash
curl -sS http://localhost:9377/health | jq '.proxyMode, .proxyServer'
```

When `proxyMode: null` shows up in `/health`, the env vars were not picked up — usually because they were set after the server was already running. Always restart after changing proxy env vars.

## Known limitations

- **Firefox base version** — current Camoufox binary is rebased from Firefox ~135 (March 2025 build). Live Firefox is 149+. No known BB-grade WAF checks UA recency, but worth noting.
- **Canvas randomization OFF by default** — Canvas1 and Canvas2 hashes will be identical across requests. If a target fingerprints via canvas hashing, enable per-session randomization (check Camoufox docs for the flag).
- **Datacenter IP weakness** — CF/Akamai heavily weight IP reputation. Without a residential proxy, expect CF Turnstile widgets on strict targets even though the underlying fingerprint is clean.
- **Firefox-only** — anything expecting Chromium DevTools Protocol (CDP), `chrome.debugger`, or specific Chrome quirks won't work.
- **No tab persistence across restarts** — server restart drops all sessions and tabs. Re-import cookies after restart.
- **One Camoufox process** — server pre-warms a single browser and reuses it. High parallelism requires multiple ports or a bigger rebuild.

## Evidence capture rules

When capturing screenshots for a BB report:

1. **Always include the URL bar / title** — use `?fullPage=true` so the tab chrome is visible if the browser renders it.
2. **Name screenshots by report step**: `evidence/step_N_short_description.png`. The framework's `NEVER HALLUCINATE FILES` rule applies — verify the file exists with `ls` before referencing it in a report.
3. **Pair every click/type with a before/after screenshot** so the proof-of-concept is reproducible.
4. **Dump the snapshot text alongside the screenshot** — `curl .../snapshot | jq -r .snapshot > evidence/step_N.txt`. This is the agent-readable version and is often more reliable than OCR on the PNG.

## Integration points in this framework

- **`.claude/agents/browser-stealth-agent.md`** — the subagent that wraps this API for dispatched hunts (runs on `model: "inherit"`). Use this via `Agent` tool calls with `subagent_type: "browser-stealth-agent"`.
- **`rules/techniques.md`** — search for "Bypassing Bot Detection" for the discovery hook that points hunters here.
- **`tools/camofox_ctl.sh`** — lifecycle wrapper. Agents must call `start` before issuing REST requests and `stop` at the end of their task unless explicitly told to leave the server running for subsequent agents.

## Troubleshooting

**`started pid N` then `timeout waiting for /health`:** check `/tmp/camofox.log`. Common causes:
- Port 9377 already bound by a zombie process — `pkill -f "node server.js"` and retry
- Camoufox binary corrupted — `trash /root/.cache/camoufox && cd /root/tools/camofox-browser && npx camoufox-js fetch`
- `xvfb-run` missing — install with `pacman -S xorg-server-xvfb`

**Snapshot empty or `refsCount: 0` on a visible page:** the page rendered a JS-heavy SPA that hadn't finished hydrating. Either (a) navigate again and wait, or (b) call `POST /tabs/:tabId/wait` with a selector to block until the element appears.

**Every request returns 404 `Tab not found`:** the server restarted and lost session state. Create a new tab.

**`navigator.webdriver` shows as `true` on `bot.sannysoft.com`:** stealth is broken — do not trust the install. Rebuild: `cd /root/tools/camofox-browser && trash node_modules && npm install`.
