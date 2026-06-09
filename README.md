# obsidian-mcp-router-view-agent

> **Reference implementation** of the [`/view` provider contract](docs/CONTRACT.md) for [obsidian-mcp-router](https://github.com/tboome33/obsidian-mcp-router) — mints **ephemeral, one-click browser links** to a vault's live Obsidian GUI, navigated to a specific note, credentials baked into the URL.
>
> 🇫🇷 *Implémentation de référence du contrat `/view` du router — fabrique des **liens navigateur éphémères en un clic** vers le GUI Obsidian d'un vault, navigué sur la note demandée, identifiants inclus dans l'URL. [Résumé français ci-dessous.](#-version-française)*

```
Claude (any MCP client)
   │  writes a note / asks to see one
   ▼
obsidian-mcp-router            OBSIDIAN_ROUTER_VIEW_AGENT_URL → this agent
   │  GET /view?vault=alice&note=Notes/hello.md   (+ X-View-Token)
   ▼
view-agent (this repo, on the host where the GUIs live)
   │  1. reuse-or-start a cloudflared quick tunnel to that vault's GUI
   │  2. navigate the GUI's Obsidian onto the note  (Local REST API /open)
   │  3. reply {"url": "https://user:pass@<random>.trycloudflare.com/"}
   ▼
the user clicks → the live GUI opens ON the note, nothing to type
   (the tunnel auto-closes after the idle window — never permanently exposed)
```

## Why this exists

obsidian-mcp-router (≥ 0.28.0) can hand the user a **read link** whenever the AI writes or opens a note in a remote vault: explicitly via the `get_view_link` tool, automatically as a `viewLink` field on every note-write result (≥ 0.29.0), and from `open_in_obsidian` on remote vaults (≥ 0.30.0). The router doesn't know *how* those links are made — it only speaks the small HTTP contract in [docs/CONTRACT.md](docs/CONTRACT.md). **This repo is one provider of that contract**: it assumes your vaults' Obsidian GUIs run as web-streamed containers (e.g. [`linuxserver/obsidian`](https://github.com/linuxserver/docker-obsidian), Selkies) on the same host, and exposes them on demand through [Cloudflare quick tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/).

Write your own provider instead (different tunneling, a real web app with signed magic links, …) — as long as it honours the contract, the router won't know the difference.

## Requirements

- Python **3.8+** (stdlib only — no pip dependencies)
- [`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) on the machine (quick tunnels need no Cloudflare account)
- The vaults' Obsidian GUIs reachable from this machine (typically loopback container ports)
- *(optional, for on-note navigation)* each vault's [Local REST API](https://github.com/coddingtonbear/obsidian-local-rest-api) + [mcp-router-bridge](https://github.com/tboome33/obsidian-mcp-router-bridge) ≥ 0.2.0 (serves the public `/open` route)

## Quickstart

```bash
git clone https://github.com/tboome33/obsidian-mcp-router-view-agent /opt/view-agent
cd /opt/view-agent
cp config.example.json config.json        # edit: bind, vaults, GUI creds, REST endpoints
openssl rand -hex 24 > view-agent.token   # optional but recommended (2nd lock)
mkdir -p secrets                          # referenced by *_file entries in config.json
python3 view-agent.py config.json
```

Smoke-test from the machine that runs the router:

```bash
curl http://<agent-host>:27200/health
curl -H "X-View-Token: $(cat view-agent.token)" \
     "http://<agent-host>:27200/view?vault=alice&note=Notes%2Fhello.md"
```

Then configure the router instance:

```
OBSIDIAN_ROUTER_VIEW_AGENT_URL=http://<agent-host>:27200
OBSIDIAN_ROUTER_VIEW_AGENT_TOKEN=<content of view-agent.token>
```

Run it for real with **systemd** ([deploy/view-agent.service](deploy/view-agent.service)) or the **cron launcher** ([deploy/start-view-agent.sh](deploy/start-view-agent.sh), `@reboot` + `*/2` crash recovery).

## Configuration

Everything lives in `config.json` (see [config.example.json](config.example.json) — every key is documented inline). Highlights:

| Key | Default | Notes |
|---|---|---|
| `bind` / `port` | `127.0.0.1` / `27200` | Keep it on a **private** interface (loopback or VPN/WireGuard IP) + firewall the port. |
| `idle_timeout_s` | `1800` | Tunnel auto-close window. Generous = warm tunnels across a conversation. |
| `token_file` | `view-agent.token` | When the file exists, `/view` requires the matching `X-View-Token`. |
| `vaults.<name>.gui_url` | — | The local GUI the tunnel exposes. |
| `vaults.<name>.gui_user` / `gui_password[_file]` | — | Baked into the returned URL (`https://user:pass@…`). |
| `vaults.<name>.open_url` / `open_api_key[_file]` | — | Optional: navigate Obsidian onto the note before replying. |

Secrets referenced as `*_file` are re-read on every use — rotate them without restarting.

## Security model (defence in depth)

1. **Network** — the agent listens on a private interface only; firewall the port to that network (e.g. `ufw allow from <your-vpn-subnet> to any port 27200 proto tcp`).
2. **Token** — with `view-agent.token` in place, only the router (which holds the same secret) can mint links; other hosts on the private network get `401`.
3. **Ephemeral exposure** — unguessable `*.trycloudflare.com` hostnames that die after the idle window. The GUI is never a permanently exposed service.
4. **GUI auth** — the GUI's own basic-auth remains the last gate while a tunnel is up.

What the returned link contains: the GUI's user/password **in the URL** (that's the point — one click, nothing to type). Treat a minted link like a session cookie: it's as sensitive as the GUI behind it, for as long as the tunnel lives.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Stdlib-only test suite — boots the real HTTP handler on an ephemeral port with a fake tunnel runner (no cloudflared needed): contract shape, token gate, unknown-vault 400, tunnel reuse, 502 on tunnel failure, idle reaper, `/open` navigation with Bearer auth.

## Repo layout

```
view-agent.py            the agent (single file, stdlib only)
config.example.json      documented config template  (copy → config.json)
docs/CONTRACT.md         the /view provider contract (normative)
deploy/                  systemd unit + cron launcher
tests/                   unittest suite (no cloudflared required)
```

---

## 🇫🇷 Version française

**Quoi** — l'implémentation de référence du contrat `/view` d'[obsidian-mcp-router](https://github.com/tboome33/obsidian-mcp-router) : quand l'IA écrit ou ouvre une note d'un vault distant, le router demande à cet agent un **lien navigateur éphémère** vers le GUI Obsidian du vault (conteneur streamé type Selkies), **navigué sur la note**, identifiants inclus dans l'URL — un clic, rien à taper. Le tunnel (Cloudflare quick tunnel) se ferme tout seul après la fenêtre d'inactivité : le GUI n'est jamais exposé en permanence.

**Modèle provider** — le router ne dépend QUE du contrat HTTP documenté dans [docs/CONTRACT.md](docs/CONTRACT.md) (`GET /view?vault=&note=` → `{"url": …}`), pas de cette implémentation. Ce dépôt en est *un* fournisseur possible ; écrivez le vôtre (autre tunneling, web app à magic-links signés…) et le router n'y verra que du feu.

**Sécurité (défense en profondeur)** — ① l'agent n'écoute que sur un réseau **privé** (loopback ou IP VPN/WireGuard, pare-feu sur le port) ; ② **token partagé** optionnel (`view-agent.token` ↔ `OBSIDIAN_ROUTER_VIEW_AGENT_TOKEN`, en-tête `X-View-Token`) pour que seul le router puisse fabriquer des liens ; ③ tunnels **éphémères** à hostname imprévisible ; ④ l'auth basique du GUI reste le dernier verrou. Un lien fabriqué se traite comme un cookie de session.

**Démarrage** — `cp config.example.json config.json` (tout y est commenté), `openssl rand -hex 24 > view-agent.token`, `python3 view-agent.py config.json`, puis côté router : `OBSIDIAN_ROUTER_VIEW_AGENT_URL` + `OBSIDIAN_ROUTER_VIEW_AGENT_TOKEN`. Déploiement durable via systemd ou cron (`deploy/`). Tests : `python3 -m unittest discover -s tests` (sans cloudflared). **Python 3.8+ stdlib uniquement.**

## License

[Apache-2.0](LICENSE) — same as obsidian-mcp-router.
