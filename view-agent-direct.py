#!/usr/bin/env python3
"""
view-agent-direct — a TUNNEL-LESS provider of the obsidian-mcp-router `/view` contract.

When to use it instead of view-agent.py
---------------------------------------
Use it when the reader can ALREADY reach the vault's web-streamed Obsidian GUI (e.g. a
Selkies container) over a private network such as WireGuard. A Cloudflare tunnel adds
nothing there, and the bridge's `/open` route stays loopback-only by design, so a link
straight to `/open` clicked from another machine gets `403 loopback only`.

What it does
------------
    GET /view?vault=<name>&note=<vault-relative-path>
      returns {"url": "<self_url>/go?v=<vault>&n=<note>[&h=<anchor>][&e=<exp>]&s=<sig>"}
      — a link to THIS agent, HMAC-signed, pure computation (no navigation, no I/O), and
      stable in the chat history unless `link_ttl_s` is set.

    GET /go?v=&n=[&h=][&e=]&s=      (the reader's browser, on click)
      1. verifies the signature (constant-time) and the optional expiry,
      2. navigates the vault's Obsidian onto the note by calling the bridge's `/open`
         route FROM THE CONTAINER'S LOOPBACK (`docker exec <container> curl ...`), so the
         bridge's loopback guard is satisfied without being relaxed,
      3. answers 302 to the vault's `public_url` (the GUI).
      For a vault opened in the READER'S OWN desktop Obsidian (`open_mode: obsidian-uri`),
      steps 2-3 become a single 302 to `obsidian://open?vault=…&file=…`: nothing is driven
      from this host, the reader's Obsidian opens the note itself.
      A failed navigation yields an explicit 502 HTML page with a link to the GUI — never
      a silent redirect.

Navigating on click (not on /view) is deliberate: the router calls /view eagerly on every
note write, and navigating there would make Obsidian jump on each write. Set
`navigate_on_view: true` to navigate on both. See docs/CONTRACT.md, "Providers without a
tunnel".

Routes
------
    GET /health   — token-free, leaks nothing actionable (served vault names only)
    GET /view     — X-View-Token required when `token_file` exists
    GET /go       — signature required when a signing secret exists

Security posture
----------------
    1. NETWORK — bind to a private interface (loopback / WireGuard IP), firewall the port.
       The reader's browser must reach this agent too (it follows /go).
    2. TOKEN   — only the router (X-View-Token) can mint links.
    3. SIGNED LINKS — /go refuses any v/n/h/e the agent did not sign, so another host on
       the private network cannot drive the vault's Obsidian to arbitrary paths.
    4. GUI AUTH — the GUI is already private; the link exposes nothing new, it only
       navigates and redirects.

Python 3.8+ stdlib only — no pip dependencies. Configuration: see config.direct.example.json.
"""
import hashlib
import hmac
import html
import json
import ntpath
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_CONFIG = {
    "bind": "127.0.0.1",
    "port": 27200,
    # Base URL under which the READER'S BROWSER reaches this agent (used to compose /go
    # links). Empty → derived from bind:port.
    "self_url": "",
    # Shared secret with the router (X-View-Token). Absent file = no token gate.
    "token_file": "view-agent.token",
    # HMAC secret for /go links. Absent file = sign with the token; both absent = unsigned
    # links (the private network is then the only lock).
    "link_secret_file": "link.secret",
    # Lifetime of /go links in seconds; 0 = no expiry (links stay valid in the chat history).
    "link_ttl_s": 0,
    # Also navigate Obsidian when /view is called. Off by default: the router calls /view
    # on every note write, which would make Obsidian jump on each write.
    "navigate_on_view": False,
    # vault name -> per-vault settings; see config.direct.example.json.
    "vaults": {},
}

VAULT_REQUIRED = ("public_url",)       # except open_mode obsidian-uri (see load_config)
VAULT_OPTIONAL = (
    "open_mode",          # "docker-exec" (default) | "http" | "none" | "obsidian-uri"
    "obsidian_vault",     # obsidian-uri: the vault's name as the reader's Obsidian knows it
    "container",          # docker-exec: container name
    "open_port",          # docker-exec: Local REST API HTTP port (insecurePort) INSIDE the container
    "open_url",           # http: Local REST API base URL (the bridge must see the call as loopback)
    "docker_path",        # docker-exec: docker binary (default "docker")
    "curl_path",          # docker-exec: curl binary INSIDE the container (default "curl")
)


# ----------------------------------------------------------------------------- config

def load_config(path):
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise ValueError("config not found: %s (copy config.direct.example.json)" % path)
    except json.JSONDecodeError as e:
        raise ValueError("config %s: invalid JSON: %s" % (path, e))

    cfg = dict(DEFAULT_CONFIG)
    cfg.update(raw or {})
    cfg["_dir"] = os.path.dirname(os.path.abspath(path))

    if not isinstance(cfg.get("vaults"), dict) or not cfg["vaults"]:
        raise ValueError('config requires a non-empty "vaults" object')
    for name, v in cfg["vaults"].items():
        if not isinstance(v, dict):
            raise ValueError('vault "%s": must be an object' % name)
        mode = v.get("open_mode", "docker-exec")
        if mode not in ("docker-exec", "http", "none", "obsidian-uri"):
            raise ValueError('vault "%s": open_mode must be docker-exec | http | none | obsidian-uri' % name)
        # A desktop vault has no web GUI: it is opened by the reader's own Obsidian.
        required = () if mode == "obsidian-uri" else VAULT_REQUIRED
        for k in required:
            if not v.get(k):
                raise ValueError('vault "%s": missing required key "%s"' % (name, k))
        unknown = [k for k in v if not k.startswith("_") and k not in VAULT_REQUIRED + VAULT_OPTIONAL]
        if unknown:
            raise ValueError('vault "%s": unknown key(s) %s' % (name, ", ".join(unknown)))
        if mode == "obsidian-uri" and not (isinstance(v.get("obsidian_vault"), str) and v["obsidian_vault"].strip()):
            raise ValueError('vault "%s": open_mode obsidian-uri requires "obsidian_vault"' % name)
        if mode == "docker-exec" and not (v.get("container") and v.get("open_port")):
            raise ValueError('vault "%s": open_mode docker-exec requires "container" and "open_port"' % name)
        if mode == "http" and not v.get("open_url"):
            raise ValueError('vault "%s": open_mode http requires "open_url"' % name)
    if not isinstance(cfg.get("port"), int):
        raise ValueError('"port" must be an integer')
    if not isinstance(cfg.get("link_ttl_s"), int) or cfg["link_ttl_s"] < 0:
        raise ValueError('"link_ttl_s" must be an integer >= 0')
    if not cfg.get("self_url"):
        cfg["self_url"] = "http://%s:%d" % (cfg["bind"], cfg["port"])
    cfg["self_url"] = cfg["self_url"].rstrip("/")
    return cfg


def _resolve(cfg, p):
    return p if os.path.isabs(p) else os.path.join(cfg.get("_dir", "."), p)


def read_secret_file(cfg, key):
    """("off", None) when the file is not configured or absent; ("on", value); ("error", None)
    when the file exists but is unreadable or empty (fail CLOSED, like view-agent.py)."""
    p = cfg.get(key)
    if not p:
        return ("off", None)
    try:
        with open(_resolve(cfg, p), encoding="utf-8") as f:
            val = f.read().strip()
    except FileNotFoundError:
        return ("off", None)
    except OSError as e:
        print("view-agent-direct: %s unreadable (%s) — failing closed" % (key, e), file=sys.stderr)
        return ("error", None)
    if not val:
        print("view-agent-direct: %s is EMPTY — failing closed" % key, file=sys.stderr)
        return ("error", None)
    return ("on", val)


def link_secret(cfg):
    """Link-signing secret: link_secret_file, else token_file, else none."""
    mode, val = read_secret_file(cfg, "link_secret_file")
    if mode == "error":
        return ("error", None)
    if mode == "on":
        return ("on", val)
    return read_secret_file(cfg, "token_file")


# ----------------------------------------------------------------------------- signed links

def _canonical(vault, note, anchor, exp):
    return "\n".join([vault, note, anchor or "", str(exp or 0)])


def sign(secret, vault, note, anchor, exp):
    mac = hmac.new(secret.encode("utf-8"), _canonical(vault, note, anchor, exp).encode("utf-8"),
                   hashlib.sha256)
    return mac.hexdigest()[:40]


def build_go_link(cfg, vault, note, anchor=""):
    """Compose the /go link. Signed when a secret exists; expiry from link_ttl_s."""
    exp = int(time.time()) + cfg["link_ttl_s"] if cfg["link_ttl_s"] else 0
    params = [("v", vault), ("n", note)]
    if anchor:
        params.append(("h", anchor))
    if exp:
        params.append(("e", str(exp)))
    mode, secret = link_secret(cfg)
    if mode == "error":
        raise RuntimeError("link-signing secret unreadable")
    if mode == "on":
        params.append(("s", sign(secret, vault, note, anchor, exp)))
    return "%s/go?%s" % (cfg["self_url"], urllib.parse.urlencode(params))


def verify_go(cfg, q):
    """Returns (ok, code, message, vault, note, anchor)."""
    vault = (q.get("v") or [""])[0]
    note = (q.get("n") or [""])[0]
    anchor = (q.get("h") or [""])[0]
    exp_s = (q.get("e") or ["0"])[0]
    sig = (q.get("s") or [""])[0]
    if not vault or not note:
        return (False, 400, "parameters v and n are required", vault, note, anchor)
    try:
        exp = int(exp_s)
    except ValueError:
        return (False, 400, "invalid parameter e", vault, note, anchor)
    mode, secret = link_secret(cfg)
    if mode == "error":
        return (False, 503, "link-signing secret unreadable on the agent", vault, note, anchor)
    if mode == "on":
        expected = sign(secret, vault, note, anchor, exp)
        if not hmac.compare_digest(sig.encode("utf-8", "replace"), expected.encode("utf-8")):
            return (False, 403, "bad signature", vault, note, anchor)
    if exp and time.time() > exp:
        return (False, 410, "link expired", vault, note, anchor)
    if vault not in cfg["vaults"]:
        return (False, 404, "unknown vault", vault, note, anchor)
    return (True, 200, "", vault, note, anchor)


# ----------------------------------------------------------------------------- navigation

def _safe_note(note):
    """Refuse what the bridge would refuse anyway (absolute path, `..`) so we never compose
    a dubious command line."""
    if not note or note.startswith("/") or note.startswith("\\"):
        return None
    # A drive prefix (C:\x, C:/x, C:x) is an absolute path for a Windows reader's Obsidian,
    # whatever the OS this agent runs on.
    if ntpath.splitdrive(note)[0]:
        return None
    if any(seg == ".." for seg in note.replace("\\", "/").split("/")):
        return None
    return note


def open_path(note, anchor):
    path = "/open/" + urllib.parse.quote(note, safe="")
    if anchor:
        path += "?h=" + urllib.parse.quote(anchor, safe="")
    return path


def obsidian_uri(vault_cfg, note=""):
    """`obsidian://open` URI for a vault opened in the reader's own desktop Obsidian.
    `open` has no heading parameter: an anchor is not carried (documented limit)."""
    uri = "obsidian://open?vault=" + urllib.parse.quote(vault_cfg["obsidian_vault"], safe="")
    if note:
        uri += "&file=" + urllib.parse.quote(note, safe="")
    return uri


def navigate(vault_cfg, note, anchor="", runner=None):
    """Navigate the vault's Obsidian onto the note. Returns (ok, detail). Never raises."""
    note = _safe_note(note)
    if not note:
        return (False, "path refused")
    mode = vault_cfg.get("open_mode", "docker-exec")
    if mode in ("none", "obsidian-uri"):
        # obsidian-uri: nothing to drive from this host, the reader's Obsidian opens it.
        return (True, "navigation disabled" if mode == "none" else "opened by the reader's Obsidian")
    try:
        if mode == "docker-exec":
            url = "http://127.0.0.1:%s%s" % (vault_cfg["open_port"], open_path(note, anchor))
            cmd = [vault_cfg.get("docker_path", "docker"), "exec", vault_cfg["container"],
                   vault_cfg.get("curl_path", "curl"), "-sS", "-o", "/dev/null",
                   "-w", "%{http_code}", "--max-time", "4", url]
            run = runner or (lambda c: subprocess.run(c, capture_output=True, text=True, timeout=8))
            r = run(cmd)
            code = (r.stdout or "").strip()[-3:]
            if r.returncode != 0:
                return (False, "docker exec rc=%s %s" % (r.returncode, (r.stderr or "").strip()[:160]))
            return (code == "200", "bridge HTTP %s" % code)
        if mode == "http":
            url = vault_cfg["open_url"].rstrip("/") + open_path(note, anchor)
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=4) as resp:
                return (resp.status == 200, "bridge HTTP %s" % resp.status)
    except Exception as e:  # best-effort per the contract: never an exception to the client
        return (False, str(e)[:160])
    return (False, "unknown mode")


# ----------------------------------------------------------------------------- HTTP

_GO_HTML = (
    "<!doctype html><meta charset=utf-8><title>Obsidian</title>"
    "<p>%s</p><p><a href=\"%s\">Open the Obsidian GUI</a></p>"
)


def make_handler(cfg, navigate_fn=None):
    nav = navigate_fn or navigate

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, code, text, href):
            body = (_GO_HTML % (html.escape(text), html.escape(href, quote=True))).encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)

            if u.path == "/health":
                return self._send(200, {"ok": True, "vaults": sorted(cfg["vaults"].keys())})

            if u.path == "/view":
                mode, tok = read_secret_file(cfg, "token_file")
                if mode == "error":
                    return self._send(503, {"error": "token file unreadable on the agent"})
                if tok is not None and not hmac.compare_digest(
                    (self.headers.get("X-View-Token") or "").encode("utf-8", "replace"),
                    tok.encode("utf-8", "replace"),
                ):
                    return self._send(401, {"error": "bad token"})
                vault = (q.get("vault") or [""])[0]
                note = (q.get("note") or [""])[0]
                anchor = (q.get("h") or [""])[0]
                vault_cfg = cfg["vaults"].get(vault)
                if vault_cfg is None:
                    return self._send(400, {"error": "unknown vault", "vaults": sorted(cfg["vaults"].keys())})
                if not note:
                    # No note: a direct link to the GUI (or the desktop vault), nothing to navigate.
                    if vault_cfg.get("open_mode") == "obsidian-uri":
                        return self._send(200, {"url": obsidian_uri(vault_cfg), "vault": vault, "kind": "obsidian-uri"})
                    return self._send(200, {"url": vault_cfg["public_url"], "vault": vault, "kind": "direct"})
                if _safe_note(note) is None:
                    return self._send(400, {"error": "bad note path"})
                navigated = None
                if cfg.get("navigate_on_view"):
                    navigated = nav(vault_cfg, note, anchor)[0]
                try:
                    link = build_go_link(cfg, vault, note, anchor)
                except RuntimeError as e:
                    return self._send(503, {"error": str(e)})
                resp = {
                    "url": link,                      # the only field the router requires
                    "vault": vault, "note": note, "kind": "direct-go",
                    "navigated_on_view": navigated,
                }
                if cfg["link_ttl_s"]:
                    # Echoed by get_view_link as expiresInSeconds. Omitted for stable links:
                    # there is nothing to expire.
                    resp["idle_timeout_s"] = cfg["link_ttl_s"]
                return self._send(200, resp)

            if u.path == "/go":
                ok, code, msg, vault, note, anchor = verify_go(cfg, q)
                if not ok:
                    return self._send(code, {"error": msg})
                vault_cfg = cfg["vaults"][vault]
                if vault_cfg.get("open_mode") == "obsidian-uri":
                    # Handed to the reader's desktop Obsidian. verify_go checks the signature,
                    # not the path: refuse absolute paths and `..` here too (unsigned setups).
                    if _safe_note(note) is None:
                        return self._send(400, {"error": "bad note path"})
                    self.send_response(302)
                    self.send_header("Location", obsidian_uri(vault_cfg, note))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                nav_ok, detail = nav(vault_cfg, note, anchor)
                target = vault_cfg["public_url"]
                if nav_ok:
                    self.send_response(302)
                    self.send_header("Location", target)
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                # Failed navigation: say so instead of redirecting silently.
                return self._html(502, "Obsidian could not be navigated to “%s” (%s)."
                                  % (note, detail), target)

            return self._send(404, {"error": "not found"})

    return Handler


def main(argv):
    config_path = (argv[1] if len(argv) > 1 else os.environ.get(
        "VIEW_AGENT_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")))
    try:
        cfg = load_config(config_path)
    except ValueError as e:
        print("view-agent-direct: %s" % e, file=sys.stderr)
        return 1
    srv = ThreadingHTTPServer((cfg["bind"], cfg["port"]), make_handler(cfg))
    print("view-agent-direct on http://%s:%d (self_url %s; vaults: %s)"
          % (cfg["bind"], cfg["port"], cfg["self_url"], ", ".join(sorted(cfg["vaults"]))))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
