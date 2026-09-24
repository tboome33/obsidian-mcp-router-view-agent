"""Tests for view-agent-direct.py — stdlib unittest only, no Docker needed.

Strategy: stand up the REAL ThreadingHTTPServer on an ephemeral loopback port with a
FAKE navigator injected into make_handler, then exercise /view and /go over actual HTTP
(token gate, signed link shape, click-time navigation, signature and expiry checks,
failure page). Pure helpers (path guard, /open encoding, docker-exec command) are tested
directly.
"""
import importlib.util
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))

# view-agent-direct.py has dashes in its name → import it via importlib.
spec = importlib.util.spec_from_file_location(
    "view_agent_direct", os.path.join(HERE, "..", "view-agent-direct.py")
)
va = importlib.util.module_from_spec(spec)
spec.loader.exec_module(va)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class AgentTestBase(unittest.TestCase):
    EXTRA = {}

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "view-agent.token"), "w") as f:
            f.write("tok-123\n")
        cfg = {
            "bind": "127.0.0.1", "port": 0, "self_url": "http://agent.test:27200",
            "token_file": "view-agent.token", "link_secret_file": "absent.secret",
            "vaults": {"alice": {"public_url": "https://gui.test:3001/", "open_mode": "none"}},
        }
        cfg.update(self.EXTRA)
        self.cfg_path = os.path.join(self.dir, "config.json")
        with open(self.cfg_path, "w") as f:
            json.dump(cfg, f)
        self.cfg = va.load_config(self.cfg_path)
        self.calls = []

        def fake_nav(vault_cfg, note, anchor=""):
            self.calls.append((note, anchor))
            return (not note.startswith("fail"), "test")

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), va.make_handler(self.cfg, fake_nav))
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def get(self, path, headers=None):
        opener = urllib.request.build_opener(NoRedirect)
        req = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            r = opener.open(req, timeout=5)
            return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def mint(self, query):
        """Call /view with the right token; return (response JSON, /go path on this server)."""
        code, _, body = self.get("/view?" + query, {"X-View-Token": "tok-123"})
        self.assertEqual(code, 200)
        data = json.loads(body)
        return data, data["url"].split("agent.test:27200", 1)[-1]


class TestView(AgentTestBase):
    def test_health_is_token_free(self):
        code, _, body = self.get("/health")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["vaults"], ["alice"])

    def test_view_requires_token(self):
        code, _, _ = self.get("/view?vault=alice&note=a.md")
        self.assertEqual(code, 401)

    def test_view_returns_signed_go_link_without_navigating(self):
        data, _ = self.mint("vault=alice&note=wiki/a%20b.md&h=Intro")
        self.assertTrue(data["url"].startswith("http://agent.test:27200/go?"))
        q = urllib.parse.parse_qs(urllib.parse.urlparse(data["url"]).query)
        self.assertEqual(q["v"], ["alice"])
        self.assertEqual(q["n"], ["wiki/a b.md"])
        self.assertEqual(q["h"], ["Intro"])
        self.assertIn("s", q)
        self.assertNotIn("idle_timeout_s", data)  # stable link: nothing to expire
        self.assertEqual(self.calls, [])

    def test_view_unknown_vault_is_4xx(self):
        code, _, _ = self.get("/view?vault=x&note=a.md", {"X-View-Token": "tok-123"})
        self.assertEqual(code, 400)

    def test_view_without_note_links_the_gui(self):
        data, _ = self.mint("vault=alice")
        self.assertEqual(data["url"], "https://gui.test:3001/")


class TestGo(AgentTestBase):
    def test_go_navigates_then_redirects(self):
        _, path = self.mint("vault=alice&note=wiki/a.md&h=Intro")
        code, headers, _ = self.get(path)
        self.assertEqual(code, 302)
        self.assertEqual(headers["Location"], "https://gui.test:3001/")
        self.assertEqual(self.calls, [("wiki/a.md", "Intro")])

    def test_go_bad_signature(self):
        code, _, _ = self.get("/go?v=alice&n=wiki/a.md&s=deadbeef")
        self.assertEqual(code, 403)
        self.assertEqual(self.calls, [])

    def test_go_failed_navigation_explains(self):
        _, path = self.mint("vault=alice&note=fail.md")
        code, _, body = self.get(path)
        self.assertEqual(code, 502)
        self.assertIn(b"gui.test:3001", body)

    def test_go_failure_page_escapes_the_note(self):
        _, path = self.mint("vault=alice&note=" + urllib.parse.quote("fail<script>.md"))
        code, _, body = self.get(path)
        self.assertEqual(code, 502)
        self.assertNotIn(b"<script>", body)
        self.assertIn(b"&lt;script&gt;", body)

    def test_expiry_is_covered_by_the_signature(self):
        self.cfg["link_ttl_s"] = 1
        link = va.build_go_link(self.cfg, "alice", "a.md")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
        q["e"] = ["1"]  # in the past, but the signature covers e → 403 first
        ok, code, *_ = va.verify_go(self.cfg, q)
        self.assertFalse(ok)
        self.assertEqual(code, 403)


class TestTtl(AgentTestBase):
    EXTRA = {"link_ttl_s": 600}

    def test_ttl_link_reports_its_lifetime(self):
        data, _ = self.mint("vault=alice&note=a.md")
        self.assertEqual(data["idle_timeout_s"], 600)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(data["url"]).query)
        self.assertIn("e", q)


class TestPure(unittest.TestCase):
    def test_refused_paths(self):
        self.assertIsNone(va._safe_note("../x.md"))
        self.assertIsNone(va._safe_note("/etc/passwd"))
        self.assertEqual(va._safe_note("wiki/x.md"), "wiki/x.md")

    def test_open_path_encoding(self):
        self.assertEqual(va.open_path("wiki/a b.md", "Intro §1"),
                         "/open/wiki%2Fa%20b.md?h=Intro%20%C2%A71")

    def test_navigate_docker_exec_builds_the_command(self):
        seen = {}

        class R:
            returncode, stdout, stderr = 0, "200", ""

        def runner(cmd):
            seen["cmd"] = cmd
            return R()
        ok, _ = va.navigate({"open_mode": "docker-exec", "container": "obs", "open_port": 27180},
                            "wiki/a.md", "", runner)
        self.assertTrue(ok)
        self.assertEqual(seen["cmd"][:3], ["docker", "exec", "obs"])
        self.assertEqual(seen["cmd"][-1], "http://127.0.0.1:27180/open/wiki%2Fa.md")

    def test_config_rejects_docker_exec_without_container(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "config.json")
            with open(p, "w") as f:
                json.dump({"vaults": {"alice": {"public_url": "https://gui.test/"}}}, f)
            with self.assertRaises(ValueError):
                va.load_config(p)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
