# The `/view` provider contract

This document is the **normative contract** between [obsidian-mcp-router](https://github.com/tboome33/obsidian-mcp-router) and a *view-link provider*. The router is coupled to **this HTTP contract only** — not to any particular implementation, host, or tunneling technology. `view-agent.py` in this repo is one reference provider (container GUIs + Cloudflare quick tunnels); anything that honours this page can replace it (a future web app could serve signed per-note magic links through the very same contract).

The router consumes the contract from `src/helpers/view-link.mjs` (`fetchViewLink`), in two modes:

| Mode | Trigger | Timeout |
|---|---|---|
| **Explicit** | the `get_view_link` MCP tool | 25 s |
| **Eager** | auto-injection of a `viewLink` field into every note-write result | **6 s** + a circuit-breaker |

A provider is configured on a router instance with two environment variables:

```
OBSIDIAN_ROUTER_VIEW_AGENT_URL    required — base URL of the provider (no path)
OBSIDIAN_ROUTER_VIEW_AGENT_TOKEN  optional — shared secret, sent as X-View-Token
```

When `OBSIDIAN_ROUTER_VIEW_AGENT_URL` is unset, the whole feature is invisible: `get_view_link` is not even listed, and writes carry no `viewLink`.

---

## Request

```
GET {base}/view?vault=<name>&note=<path>
```

| Part | Required | Semantics |
|---|---|---|
| `vault` (query) | yes | The **canonical vault name** as the router resolved it. The provider decides which vault names it serves. |
| `note` (query) | no | Vault-relative note path (URL-encoded by the router, e.g. `Voyages%2Ftrip.md`). When present, the provider SHOULD navigate the vault's UI onto that note **before** responding — best-effort: a navigation failure MUST NOT fail the response. |
| `X-View-Token` (header) | no | Present iff the router instance has `OBSIDIAN_ROUTER_VIEW_AGENT_TOKEN` set. A provider that enforces a token MUST answer `401` on a missing/wrong value. |

The router never sends a body, never uses another method, and never appends extra path segments.

## Success response

`200` with a JSON object:

| Field | Type | Required | Semantics |
|---|---|---|---|
| `url` | string, non-empty | **yes** | A **browser-ready** URL the user can click with nothing to type. If the target UI is behind basic-auth, bake the credentials in (`https://user:pass@host/`). This is the only field the router validates. |
| `idle_timeout_s` | number | recommended | Seconds of inactivity before the link dies. Echoed by `get_view_link` as `expiresInSeconds`. |
| *anything else* | — | no | Ignored by the router (the reference impl also returns `raw_url`, `vault`, `note` for debugging). |

## Error responses

Return JSON `{"error": "<human-readable reason>"}` — the router surfaces `.error` in its diagnostics. The **status-code class is semantically load-bearing** for the router's eager-path circuit-breaker:

| Class | Meaning to the router | Examples |
|---|---|---|
| **4xx** | *Per-vault / permanent* condition. Does **NOT** trip the circuit-breaker — one unsupported vault must never suppress links for healthy vaults. | `400` unknown vault · `401` bad/missing token |
| **5xx** | *Provider-health* failure (transient). Counts toward the breaker (3 consecutive transient failures → the router skips eager calls for 60 s). | `502` tunnel failed to start · `500` anything unexpected |

Transport errors and timeouts are treated like 5xx (transient).

## Timing expectations

- A **warm** target (tunnel/session already up) should answer **well under 1 s** — the eager path rides on every note write.
- A **cold** start may take ~15–18 s (cloudflared handshake). That exceeds the 6 s eager timeout: the write then carries a `viewLinkError` instead of a link, and the next call (or an explicit `get_view_link`, 25 s budget) gets the now-warm tunnel. This is expected and acceptable.
- Keep targets warm with a generous idle window (the reference default is 1800 s) so at most the **first** link of a conversation pays the cold start.

## Health endpoint (optional, recommended)

```
GET {base}/health   →  200 {"ok": true, ...}
```

Not used by the router; useful for cron-based crash recovery and monitoring (the reference launcher curls it before deciding to relaunch).

## Security expectations on a provider

1. **Listen on a private network only** (loopback or a VPN/WireGuard interface) and firewall the port accordingly. The router reaches you over that private hop.
2. **Support the token gate** so that only the router — not every host on the private network — can mint links.
3. **Keep links ephemeral**: unguessable hostnames + idle expiry. A provider must never turn a vault UI into a permanently exposed service.
4. **Never log or echo secrets** (tokens, GUI passwords, API keys) anywhere except inside the returned `url` itself.

## Worked example

```
GET http://192.0.2.10:27200/view?vault=alice&note=Notes%2Fhello.md
X-View-Token: 3f9c…

200 {"url": "https://obsidian:s3cret@random-words.trycloudflare.com/",
     "raw_url": "https://random-words.trycloudflare.com",
     "vault": "alice", "note": "Notes/hello.md", "idle_timeout_s": 1800}
```

The router then returns that `url` as `get_view_link`'s `url` field, as the `viewLink` field auto-injected into note-write results (router ≥ 0.29.0), and from `open_in_obsidian` for remote vaults (router ≥ 0.30.0).
