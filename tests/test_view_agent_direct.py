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


class TestObsidianUri(AgentTestBase):
    """A vault opened in the reader's own desktop Obsidian: no GUI, no navigation here."""
    EXTRA = {"vaults": {
        "alice": {"public_url": "https://gui.test:3001/", "open_mode": "none"},
        "desk": {"open_mode": "obsidian-uri", "obsidian_vault": "Mon vault & co"},
    }}

    def test_go_redirects_to_the_desktop_obsidian(self):
        _, path = self.mint("vault=desk&note=" + urllib.parse.quote("wiki/a b#c.md") + "&h=Intro")
        code, headers, _ = self.get(path)
        self.assertEqual(code, 302)
        self.assertEqual(headers["Location"],
                         "obsidian://open?vault=Mon%20vault%20%26%20co&file=wiki%2Fa%20b%23c.md")
        self.assertEqual(self.calls, [])  # nothing driven from this host

    def test_go_still_requires_the_signature(self):
        code, _, _ = self.get("/go?v=desk&n=wiki/a.md&s=deadbeef")
        self.assertEqual(code, 403)

    def test_go_refuses_a_traversal_even_when_signed(self):
        # /view refuses it before minting; sign it by hand to reach /go.
        link = va.build_go_link(self.cfg, "desk", "../secret.md")
        code, _, _ = self.get(link.split("agent.test:27200", 1)[-1])
        self.assertEqual(code, 400)

    def test_go_refuses_windows_and_other_absolute_paths(self):
        for bad in ("C:\\Users\\r\\secret.md", "C:/Users/r/secret.md", "c:secret.md",
                    "\\\\host\\share\\x.md", "/etc/x.md", "wiki/../../x.md"):
            link = va.build_go_link(self.cfg, "desk", bad)
            code, headers, _ = self.get(link.split("agent.test:27200", 1)[-1])
            self.assertEqual(code, 400, bad)
            self.assertNotIn("Location", headers)

    def test_go_encodes_hostile_values_into_one_file_parameter(self):
        note = "wiki/a&vault=other&file=x;Set-Cookie: y#é.md"
        link = va.build_go_link(self.cfg, "desk", note)
        code, headers, _ = self.get(link.split("agent.test:27200", 1)[-1])
        self.assertEqual(code, 302)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(headers["Location"]).query)
        self.assertEqual(q, {"vault": ["Mon vault & co"], "file": [note]})
        self.assertNotIn("Set-Cookie", headers)

    def test_view_without_note_opens_the_vault(self):
        data, _ = self.mint("vault=desk")
        self.assertEqual(data["url"], "obsidian://open?vault=Mon%20vault%20%26%20co")

    def test_config_requires_obsidian_vault_but_not_public_url(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "config.json")
            with open(p, "w") as f:
                json.dump({"vaults": {"desk": {"open_mode": "obsidian-uri"}}}, f)
            with self.assertRaises(ValueError):
                va.load_config(p)
            with open(p, "w") as f:
                json.dump({"vaults": {"desk": {"open_mode": "obsidian-uri", "obsidian_vault": "V"}}}, f)
            self.assertIn("desk", va.load_config(p)["vaults"])
            with open(p, "w") as f:
                json.dump({"vaults": {"desk": {"open_mode": "obsidian-uri", "obsidian_vault": "   "}}}, f)
            with self.assertRaises(ValueError):
                va.load_config(p)
            with open(p, "w") as f:  # the exemption is for obsidian-uri only
                json.dump({"vaults": {"a": {"open_mode": "none"}}}, f)
            with self.assertRaises(ValueError):
                va.load_config(p)
        finally:
            shutil.rmtree(d, ignore_errors=True)


ID_A = "a" * 64
ID_B = "b" * 64


def container(cid, name, ports, running=True, mounts=None):
    """A `docker inspect` object; ports = {"<inner>/tcp": [(host_ip, host_port), ...]}.
    By default the container mounts its own vault folder, /srv/vaults/<name>."""
    if mounts is None:
        mounts = [{"Type": "bind", "Source": "/srv/vaults/" + name, "Destination": "/vaults/x"}]
    return {"Id": cid, "Name": "/" + name, "State": {"Running": running}, "Mounts": mounts,
            "NetworkSettings": {"Ports": {k: [{"HostIp": ip, "HostPort": str(p)} for ip, p in v]
                                          for k, v in ports.items()}}}


VAULTS_HOST = [
    container(ID_A, "obsidian-notes", {"27180/tcp": [("0.0.0.0", 27180), ("::", 27180)],
                                        "3001/tcp": [("0.0.0.0", 3001), ("::", 3001)]}),
    container(ID_B, "obsidian-bob", {"27180/tcp": [("0.0.0.0", 27181)],
                                           "3001/tcp": [("0.0.0.0", 3002)]}),
]


class FakeDocker:
    """Records every argv and answers `docker ps` / `docker inspect` from `self.containers`."""

    def __init__(self, containers):
        self.containers = containers
        self.cmds = []
        self.ps_stdout = None       # override `docker ps` output
        self.inspect_stdout = None  # override `docker inspect` output
        self.raises = None          # exception raised by every call (docker missing)

    def __call__(self, cmd):
        self.cmds.append(list(cmd))
        if self.raises:
            raise self.raises

        class R:
            returncode, stderr = 0, ""
        r = R()
        if cmd[1] == "ps":
            r.stdout = self.ps_stdout if self.ps_stdout is not None else \
                "".join(c["Id"] + "\n" for c in self.containers)
        elif cmd[1] == "inspect":
            r.stdout = self.inspect_stdout if self.inspect_stdout is not None else \
                json.dumps([c for c in self.containers if c["Id"] in cmd[4:]])
        else:
            raise AssertionError("unexpected docker command %r" % cmd)
        return r


class DetectBase(AgentTestBase):
    """Agent on 192.0.2.1 (the server), reader's desktop on 192.0.2.10. `alice` stays
    configured; everything else is detected from the router's hints."""
    EXTRA = {"bind": "192.0.2.1", "detect": {"desktop_hosts": ["192.0.2.10"], "cache_s": 0}}
    CONTAINERS = VAULTS_HOST

    def setUp(self):
        self.docker = FakeDocker([dict(c) for c in self.CONTAINERS])
        super().setUp()


def _serve_with_docker(self):
    """AgentTestBase.setUp builds the server without a docker runner: rebuild it with one."""
    self.srv.shutdown()
    self.srv.server_close()

    def fake_nav(vault_cfg, note, anchor=""):
        self.calls.append((note, anchor))
        self.nav_cfgs.append(vault_cfg)
        return (not note.startswith("fail"), "test")

    self.nav_cfgs = []
    self.srv = ThreadingHTTPServer(("127.0.0.1", 0), va.make_handler(self.cfg, fake_nav, self.docker))
    self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]
    threading.Thread(target=self.srv.serve_forever, daemon=True).start()


class TestDetectContainer(DetectBase):
    def setUp(self):
        super().setUp()
        _serve_with_docker(self)

    def view(self, query):
        return self.get("/view?" + query, {"X-View-Token": "tok-123"})

    def test_container_vault_is_detected_and_navigated_by_id(self):
        data, path = self.mint("vault=notes&note=wiki/a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(data["open_mode"], "docker-exec")
        self.assertEqual(data["source"], "container obsidian-notes")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(data["url"]).query)
        self.assertEqual(q["r"], ["http://192.0.2.1:27180"])
        code, headers, _ = self.get(path)
        self.assertEqual(code, 302)
        self.assertEqual(headers["Location"], "https://192.0.2.1:3001/")
        self.assertEqual(self.nav_cfgs[-1]["container"], ID_A)       # the hex ID, not a name
        self.assertEqual(self.nav_cfgs[-1]["open_port"], 27180)

    def test_published_port_maps_to_the_inner_port_and_its_gui(self):
        data, path = self.mint("vault=bob&note=a.md&rest=" + urllib.parse.quote("https://192.0.2.1:27181"))
        code, headers, _ = self.get(path)
        self.assertEqual(headers["Location"], "https://192.0.2.1:3002/")
        self.assertEqual(self.nav_cfgs[-1]["container"], ID_B)
        self.assertEqual(self.nav_cfgs[-1]["open_port"], 27180)       # inside the container

    def test_docker_is_only_called_with_fixed_argv(self):
        self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(self.docker.cmds, [
            ["docker", "ps", "--no-trunc", "-q"],
            ["docker", "inspect", "--type", "container", ID_A, ID_B],
        ])

    def test_manual_config_wins_over_detection(self):
        data, path = self.mint("vault=alice&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(data["source"], "config")
        self.assertNotIn("r=", data["url"])
        code, headers, _ = self.get(path)
        self.assertEqual(headers["Location"], "https://gui.test:3001/")
        self.assertEqual(self.docker.cmds, [])

    def test_unknown_vault_without_hints_is_still_400(self):
        code, _, body = self.view("vault=x&note=a.md")
        self.assertEqual(code, 400)
        self.assertEqual(json.loads(body)["error"], "unknown vault")

    def test_no_container_on_that_port_is_an_explicit_400(self):
        code, _, body = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27999"))
        self.assertEqual(code, 400)
        self.assertIn("27999", json.loads(body)["error"])

    def test_port_published_on_another_ip_does_not_match(self):
        self.docker.containers = [container(ID_A, "obs", {"27180/tcp": [("127.0.0.1", 27180)],
                                                          "3001/tcp": [("0.0.0.0", 3001)]})]
        code, _, _ = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 400)

    def test_two_containers_on_one_port_is_ambiguous(self):
        self.docker.containers = [
            container(ID_A, "one", {"27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]}),
            container(ID_B, "two", {"27180/tcp": [("192.0.2.1", 27180)], "3001/tcp": [("0.0.0.0", 3002)]}),
        ]
        code, _, body = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 400)
        self.assertIn("one, two", json.loads(body)["error"])

    def test_container_without_gui_port_is_an_explicit_400(self):
        self.docker.containers = [container(ID_A, "obs", {"27180/tcp": [("0.0.0.0", 27180)]})]
        code, _, body = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 400)
        self.assertIn("GUI", json.loads(body)["error"])

    def test_stopped_container_is_ignored(self):
        self.docker.containers = [dict(VAULTS_HOST[0], State={"Running": False})]
        code, _, _ = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 400)

    def test_unexpected_docker_ps_output_fails_closed_before_inspect(self):
        self.docker.ps_stdout = ID_A + "\n--format={{.Name}};id\n"
        code, _, _ = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 503)
        self.assertEqual([c[1] for c in self.docker.cmds], ["ps"])

    def test_inspect_object_with_a_forged_id_is_ignored(self):
        forged = container("c" * 64, "evil", {"27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]})
        self.docker.ps_stdout = ID_A + "\n"             # ps never listed c…c
        self.docker.inspect_stdout = json.dumps([forged])
        code, _, _ = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 400)

    def test_docker_unavailable_is_503(self):
        self.docker.raises = FileNotFoundError("docker")
        code, _, _ = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 503)

    def test_go_redetects_and_explains_when_the_container_is_gone(self):
        _, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.docker.containers = []
        code, headers, body = self.get(path)
        self.assertEqual(code, 400)             # the classification error's own code, not 502
        self.assertNotIn("Location", headers)
        self.assertIn(b"27180", body)
        self.assertEqual(self.calls, [])

    def test_hint_is_covered_by_the_signature(self):
        _, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        tampered = path.replace("27180", "27181")
        self.assertEqual(self.get(tampered)[0], 403)
        stripped = "&".join(p for p in path.split("&") if not p.startswith("r="))
        self.assertEqual(self.get(stripped)[0], 403)
        self.assertEqual(self.calls, [])

    def test_hint_cannot_be_added_to_a_legacy_link(self):
        link = va.build_go_link(self.cfg, "ghost", "a.md")    # legacy format, unknown vault
        path = link.split("agent.test:27200", 1)[-1] + "&r=" + urllib.parse.quote("http://192.0.2.1:27180")
        self.assertEqual(self.get(path)[0], 403)

    def test_loopback_hint_uses_the_readers_host_for_the_gui(self):
        _, path = self.mint("vault=x&note=a.md&rest=" + urllib.parse.quote("http://127.0.0.1:27180"))
        self.assertEqual(self.get(path)[1]["Location"], "https://agent.test:3001/")

    def test_malformed_rest_hint_is_a_400_not_a_dropped_connection(self):
        code, _, body = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://[::1:80"))
        self.assertEqual(code, 400)
        self.assertIn("rest hint", json.loads(body)["error"])

    def test_https_hint_navigates_over_https_on_loopback(self):
        _, path = self.mint("vault=bob&note=a.md&rest=" + urllib.parse.quote("https://192.0.2.1:27181"))
        self.get(path)
        self.assertEqual(self.nav_cfgs[-1]["open_scheme"], "https")
        _, path = self.mint("vault=v&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.get(path)
        self.assertEqual(self.nav_cfgs[-1]["open_scheme"], "http")

    def test_gui_bound_to_loopback_is_not_offered_to_the_reader(self):
        self.docker.containers = [container(ID_A, "obs", {"27180/tcp": [("127.0.0.1", 27180)],
                                                          "3001/tcp": [("127.0.0.1", 3001)]})]
        code, _, body = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://127.0.0.1:27180"))
        self.assertEqual(code, 400)
        self.assertIn("GUI", json.loads(body)["error"])

    def test_malformed_docker_inspect_shapes_never_crash(self):
        weird = [{"Id": ID_A, "State": "running", "NetworkSettings": {"Ports": {}}},
                 {"Id": ID_B, "State": {"Running": True}, "NetworkSettings": {"Ports": [1, 2]}}]
        for objs in (weird, [dict(container(ID_A, "o", {"27180/tcp": [("0.0.0.0", 27180)]}),
                                  NetworkSettings={"Ports": {"27180/tcp": ["x", {"HostPort": "\u00b2"}]}})],
                     [{"Id": ID_A, "State": {"Running": True}, "NetworkSettings": 5}], "nope"):
            self.docker.ps_stdout = ID_A + "\n" + ID_B + "\n"
            self.docker.inspect_stdout = json.dumps(objs)
            code, _, _ = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
            self.assertIn(code, (400, 503), repr(objs))

    def test_one_malformed_bind_does_not_hide_the_container(self):
        c = container(ID_A, "obs", {"27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]})
        c["NetworkSettings"]["Ports"]["27180/tcp"].insert(0, "x")
        c["NetworkSettings"]["Ports"]["9/tcp"] = [{"HostPort": "\u00b2"}]
        self.docker.containers = [c]
        data, _ = self.mint("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(data["source"], "container obs")

    def test_localhost_hint_matches_a_loopback_binding(self):
        self.docker.containers = [container(ID_A, "obs", {"27180/tcp": [("127.0.0.1", 27180)],
                                                          "3001/tcp": [("0.0.0.0", 3001)]})]
        data, _ = self.mint("vault=x&note=a.md&rest=" + urllib.parse.quote("http://localhost:27180"))
        self.assertEqual(data["source"], "container obs")

    def test_detection_link_for_a_since_configured_vault_is_refused(self):
        # Minted by detection, then the same name was configured (maybe pointing elsewhere):
        # the old link must not follow the configuration unchecked.
        hints = {"rest": "http://192.0.2.1:27180", "container": "obsidian-notes", "vault_id": "0" * 16}
        link = va.build_go_link(self.cfg, "alice", "a.md", "", hints)
        code, headers, _ = self.get(link.split("agent.test:27200", 1)[-1])
        self.assertEqual(code, 409)
        self.assertNotIn("Location", headers)
        self.assertEqual(self.calls, [])

    def test_ipv4_mapped_local_address_is_local(self):
        data, _ = self.mint("vault=x&note=a.md&rest=" + urllib.parse.quote("http://[::ffff:192.0.2.1]:27180"))
        self.assertEqual(data["source"], "container obsidian-notes")

    def test_docker_down_is_remembered_briefly(self):
        self.cfg["detect"]["cache_s"] = 60
        self.docker.raises = FileNotFoundError("docker")
        for _ in range(3):
            self.assertEqual(self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))[0], 503)
        self.assertEqual(len(self.docker.cmds), 1)

    def test_unreadable_secret_is_503_on_the_detection_path(self):
        os.mkdir(os.path.join(self.dir, "absent.secret"))          # a directory: unreadable
        code, _, _ = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 503)

    def test_unexpected_exception_is_a_json_500(self):
        self.srv.shutdown()
        self.srv.server_close()

        def boom(*a, **k):
            raise KeyError("x")
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), va.make_handler(self.cfg, boom, self.docker))
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        _, path = self.mint("vault=alice&note=a.md")
        code, _, body = self.get(path)
        self.assertEqual(code, 500)
        self.assertEqual(json.loads(body), {"error": "internal error"})

    # --- the vault's identity is signed: a port taken over by another vault is refused
    def test_port_taken_over_by_another_container_is_refused_at_go(self):
        _, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.docker.containers = [container("e" * 64, "obsidian-eve", {
            "27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]})]
        code, headers, body = self.get(path)
        self.assertEqual(code, 409)
        self.assertNotIn("Location", headers)
        self.assertIn(b"obsidian-eve", body)
        self.assertEqual(self.calls, [])

    def test_same_name_mounting_another_vault_is_refused_at_go(self):
        _, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        other = container("e" * 64, "obsidian-notes", {                # same name, another vault
            "27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]},
            mounts=[{"Type": "bind", "Source": "/srv/vaults/eve", "Destination": "/vaults/x"}])
        self.docker.containers = [other]
        code, headers, _ = self.get(path)
        self.assertEqual(code, 409)
        self.assertNotIn("Location", headers)
        self.assertEqual(self.calls, [])

    def _takeover(self, mounts):
        _, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.docker.containers = [container("e" * 64, "obsidian-notes", {
            "27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]}, mounts=mounts)]
        return self.get(path)

    def test_swapped_destinations_are_another_vault(self):
        a = {"Type": "bind", "Source": "/srv/a", "Destination": "/vault"}
        b = {"Type": "bind", "Source": "/srv/b", "Destination": "/backup"}
        self.docker.containers = [container(ID_A, "obsidian-notes", {
            "27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]}, mounts=[a, b])]
        code, headers, _ = self._takeover([dict(a, Destination="/backup"), dict(b, Destination="/vault")])
        self.assertEqual(code, 409)
        self.assertNotIn("Location", headers)
        self.assertEqual(self.calls, [])

    def test_mount_order_does_not_change_the_identity(self):
        a = {"Type": "bind", "Source": "/srv/a", "Destination": "/vault"}
        b = {"Type": "volume", "Name": "notes-config", "Destination": "/config"}
        self.docker.containers = [container(ID_A, "obsidian-notes", {
            "27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]}, mounts=[a, b])]
        code, _, _ = self._takeover([b, a])                             # recreated, order shuffled
        self.assertEqual(code, 302)

    def test_another_named_volume_is_another_vault(self):
        v = {"Type": "volume", "Name": "notes-data", "Destination": "/vault"}
        self.docker.containers = [container(ID_A, "obsidian-notes", {
            "27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]}, mounts=[v])]
        self.assertEqual(self._takeover([dict(v, Name="eve-data")])[0], 409)

    def test_another_volume_subpath_is_another_vault(self):
        # Real `docker inspect` shape: the resolved mount has no subpath, the spec in
        # HostConfig.Mounts carries it (Compose long syntax `volume: {subpath: ...}`).
        def vault_on(sub):
            c = container(ID_A, "obsidian-notes", {"27180/tcp": [("0.0.0.0", 27180)],
                                                   "3001/tcp": [("0.0.0.0", 3001)]},
                          mounts=[{"Type": "volume", "Name": "vaults", "Destination": "/vault"}])
            c["HostConfig"] = {"Mounts": [{"Type": "volume", "Source": "vaults", "Target": "/vault",
                                           "VolumeOptions": {"Subpath": sub}}]}
            return c
        self.docker.containers = [vault_on("alice")]
        _, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.docker.containers = [vault_on("bob")]
        code, headers, _ = self.get(path)
        self.assertEqual(code, 409)
        self.assertNotIn("Location", headers)
        self.docker.containers = [vault_on("alice")]                   # back: same identity
        self.assertEqual(self.get(path)[0], 302)

    def test_identity_fields_sent_to_view_are_ignored(self):
        data, _ = self.mint("vault=notes&note=a.md&container=evil&vault_id=" + "0" * 16
                            + "&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        q = urllib.parse.parse_qs(urllib.parse.urlparse(data["url"]).query)
        self.assertEqual(q["c"], ["obsidian-notes"])
        self.assertNotEqual(q["k"], ["0" * 16])

    def test_container_mounting_nothing_is_not_a_vault(self):
        self.docker.containers = [container(ID_A, "obs", {"27180/tcp": [("0.0.0.0", 27180)],
                                                          "3001/tcp": [("0.0.0.0", 3001)]}, mounts=[])]
        code, _, body = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 400)
        self.assertIn("mounts nothing", json.loads(body)["error"])

    def test_vault_identity_is_signed(self):
        data, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        k = urllib.parse.parse_qs(urllib.parse.urlparse(data["url"]).query)["k"][0]
        self.assertRegex(k, r"^[0-9a-f]{16}$")
        self.assertEqual(self.get(path.replace("k=" + k, "k=" + "0" * 16))[0], 403)

    def test_recreated_container_keeps_its_name_and_is_found_again(self):
        _, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.docker.containers = [dict(VAULTS_HOST[0], Id="f" * 64)]   # same name, new ID
        code, headers, _ = self.get(path)
        self.assertEqual(code, 302)
        self.assertEqual(self.nav_cfgs[-1]["container"], "f" * 64)

    def test_container_identity_is_signed_and_never_taken_from_view(self):
        data, path = self.mint("vault=notes&note=a.md&container=obsidian-bob&rest="
                               + urllib.parse.quote("http://192.0.2.1:27180"))
        q = urllib.parse.parse_qs(urllib.parse.urlparse(data["url"]).query)
        self.assertEqual(q["c"], ["obsidian-notes"])                  # from Docker, not the request
        self.assertEqual(self.get(path.replace("c=obsidian-notes", "c=obsidian-bob"))[0], 403)

    def test_hint_link_without_container_identity_is_refused(self):
        link = va.build_go_link(self.cfg, "notes", "a.md", "", {"rest": "http://192.0.2.1:27180"})
        code, _, _ = self.get(link.split("agent.test:27200", 1)[-1])
        self.assertEqual(code, 409)
        self.assertEqual(self.calls, [])

    # --- a click sees Docker as it is now, whatever the cache
    def test_go_bypasses_the_inventory_cache(self):
        self.cfg["detect"]["cache_s"] = 60
        _, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.docker.containers = [container("e" * 64, "obsidian-eve", {
            "27180/tcp": [("0.0.0.0", 27180)], "3001/tcp": [("0.0.0.0", 3001)]})]
        self.assertEqual(self.get(path)[0], 409)       # cached inventory would still say notes
        self.docker.containers = [dict(VAULTS_HOST[0], Id="f" * 64)]
        self.assertEqual(self.get(path)[0], 302)
        self.assertEqual(self.nav_cfgs[-1]["container"], "f" * 64)

    def test_docker_down_at_click_is_503(self):
        _, path = self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.docker.raises = FileNotFoundError("docker")
        self.assertEqual(self.get(path)[0], 503)

    # --- address families
    def test_ipv4_only_publication_does_not_answer_an_ipv6_hint(self):
        self.docker.containers = [container(ID_A, "obs", {"27180/tcp": [("0.0.0.0", 27180)],
                                                          "3001/tcp": [("0.0.0.0", 3001), ("::", 3001)]})]
        code, _, _ = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://[::1]:27180"))
        self.assertEqual(code, 400)

    def test_ipv6_only_publication_does_not_answer_an_ipv4_hint(self):
        self.docker.containers = [container(ID_A, "obs", {"27180/tcp": [("::", 27180)],
                                                          "3001/tcp": [("0.0.0.0", 3001), ("::", 3001)]})]
        code, _, _ = self.view("vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 400)

    def test_ipv6_hint_matches_an_ipv6_publication(self):
        data, _ = self.mint("vault=x&note=a.md&rest=" + urllib.parse.quote("http://[::1]:27180"))
        self.assertEqual(data["source"], "container obsidian-notes")    # published on :: too

    def test_docker_inventory_is_cached(self):
        self.cfg["detect"]["cache_s"] = 60
        for _ in range(3):
            self.mint("vault=notes&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual([c[1] for c in self.docker.cmds], ["ps", "inspect"])


class TestDetectDesktop(DetectBase):
    def setUp(self):
        super().setUp()
        _serve_with_docker(self)

    def test_desktop_vault_redirects_to_obsidian_without_docker(self):
        data, path = self.mint("vault=carol&note=wiki/a.md&rest=" + urllib.parse.quote("http://192.0.2.10:27190")
                               + "&obsidian_name=" + urllib.parse.quote("Carol notes et co"))
        self.assertEqual(data["open_mode"], "obsidian-uri")
        code, headers, _ = self.get(path)
        self.assertEqual(code, 302)
        self.assertEqual(headers["Location"],
                         "obsidian://open?vault=Carol%20notes%20et%20co&file=wiki%2Fa.md")
        self.assertEqual(self.docker.cmds, [])
        self.assertEqual(self.calls, [])

    def test_obsidian_name_is_covered_by_the_signature(self):
        _, path = self.mint("vault=carol&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.10:27190")
                            + "&obsidian_name=Real")
        self.assertEqual(self.get(path.replace("o=Real", "o=Other"))[0], 403)

    def test_desktop_vault_without_obsidian_name_is_an_explicit_400(self):
        code, _, body = self.get("/view?vault=carol&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.10:27190"),
                                 {"X-View-Token": "tok-123"})
        self.assertEqual(code, 400)
        self.assertIn("obsidian_name", json.loads(body)["error"])

    def test_unlisted_remote_host_is_never_guessed(self):
        code, _, body = self.get("/view?vault=r&note=a.md&obsidian_name=X&rest="
                                 + urllib.parse.quote("http://192.0.2.11:27190"), {"X-View-Token": "tok-123"})
        self.assertEqual(code, 400)
        self.assertIn("cannot classify", json.loads(body)["error"])

    def test_desktop_link_without_note_opens_the_vault(self):
        data, _ = self.mint("vault=carol&rest=" + urllib.parse.quote("http://192.0.2.10:27190")
                            + "&obsidian_name=V")
        self.assertEqual(data["url"], "obsidian://open?vault=V")

    def test_desktop_go_still_refuses_traversal(self):
        hints = {"rest": "http://192.0.2.10:27190", "obsidian_name": "V"}
        link = va.build_go_link(self.cfg, "router", "../x.md", "", hints)
        self.assertEqual(self.get(link.split("agent.test:27200", 1)[-1])[0], 400)

    def test_invalid_obsidian_name_is_refused(self):
        for bad in ("a\nb", " lead", "x" * 256):
            code, _, _ = self.get("/view?vault=r&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.10:1")
                                  + "&obsidian_name=" + urllib.parse.quote(bad), {"X-View-Token": "tok-123"})
            self.assertEqual(code, 400, repr(bad))


class TestDetectNeedsLocks(DetectBase):
    """Without a token AND a signing secret, detection is refused (links always signed)."""

    def setUp(self):
        super().setUp()
        os.remove(os.path.join(self.dir, "view-agent.token"))     # no token, no secret at all
        _serve_with_docker(self)

    def test_detection_refused_without_secrets(self):
        code, _, body = self.get("/view?vault=x&note=a.md&rest=" + urllib.parse.quote("http://192.0.2.1:27180"))
        self.assertEqual(code, 400)
        self.assertIn("requires", json.loads(body)["error"])
        self.assertEqual(self.docker.cmds, [])

    def test_unsigned_hint_link_is_refused_at_go(self):
        path = "/go?v=x&n=a.md&r=" + urllib.parse.quote("http://192.0.2.1:27180")
        self.assertEqual(self.get(path)[0], 403)
        self.assertEqual(self.docker.cmds, [])

    def test_configured_vault_keeps_working_unsigned(self):
        self.assertEqual(self.get("/go?v=alice&n=a.md")[0], 302)


class TestDetectPure(unittest.TestCase):
    def test_rest_hint_refusals(self):
        for bad in ("ftp://192.0.2.1:21", "http://u:p@192.0.2.1:27180", "http://192.0.2.1@evil:27180",
                    "http://192.0.2.1", "http://192.0.2.1:27180/x", "http://192.0.2.1:27180?a=1",
                    "http://192.0.2.1:27180#f", "http://192.0.2.1:99999", "http://bad_host:1",
                    "http://192.0.2.1:27180\\@x", "http://a b:1", "http://x:1\n", "", "192.0.2.1:27180",
                    "http://$(id):1", "http://-x:1", "http://[::1:80", "http://[::1]x:80",
                    "http://[fe80::1%25eth0]:27124"):
            with self.assertRaises(va.DetectError, msg=bad):
                va.parse_rest_hint(bad)

    def test_rest_hint_normalization(self):
        self.assertEqual(va.parse_rest_hint("HTTP://LocalHost:27180/"),
                         ("http://localhost:27180", "localhost", 27180, "http"))
        self.assertEqual(va.parse_rest_hint("http://[::ffff:192.0.2.1]:1")[1], "192.0.2.1")  # one spelling
        self.assertEqual(va.parse_rest_hint("https://[::1]:27124")[0], "https://[::1]:27124")

    def test_desktop_hosts_accept_cidr_and_names(self):
        nets = va._load_detect({"desktop_hosts": ["192.0.2.0/28", "pc.wg"]})["_desktop"]
        self.assertTrue(va._host_in("192.0.2.10", nets))
        self.assertFalse(va._host_in("192.0.2.17", nets))
        self.assertTrue(va._host_in("pc.wg", nets))
        self.assertFalse(va._host_in("::1", nets))

    def test_ipv4_mapped_desktop_host_matches_the_normalized_hint(self):
        nets = va._load_detect({"desktop_hosts": ["::ffff:10.0.0.5"]})["_desktop"]
        self.assertTrue(va._host_in(va.parse_rest_hint("http://10.0.0.5:1")[1], nets))
        with self.assertRaises(ValueError):
            va._load_detect({"desktop_hosts": ["::ffff:10.0.0.0/120"]})

    def test_detect_config_validation(self):
        for bad in ({"desktop_hosts": ["not a host!"]}, {"gui_url": "https://{host.__class__}:{port}/"},
                    {"gui_url": "https://x/"}, {"gui_url": "file:///{port}"}, {"bogus": 1},
                    {"gui_container_ports": []}, {"gui_container_ports": [True]}, {"enabled": "yes"},
                    {"cache_s": -1}, {"local_hosts": "192.0.2.1"}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                va._load_detect(bad)

    def test_a_host_cannot_be_both_local_and_desktop(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "config.json")
            with open(p, "w") as f:
                json.dump({"bind": "192.0.2.1", "vaults": {}, "detect": {"desktop_hosts": ["192.0.2.0/24"]}}, f)
            with self.assertRaises(ValueError):
                va.load_config(p)
            with open(p, "w") as f:
                json.dump({"vaults": {"a": {"public_url": "u", "container": "c", "open_port": 1,
                                            "open_scheme": "ftp"}}}, f)
            with self.assertRaises(ValueError):
                va.load_config(p)
            with open(p, "w") as f:  # detection lets "vaults" be empty; disabling it does not
                json.dump({"vaults": {}, "detect": {"enabled": False}}, f)
            with self.assertRaises(ValueError):
                va.load_config(p)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_detected_container_navigates_by_id_with_fixed_argv(self):
        seen = {}

        class R:
            returncode, stdout, stderr = 0, "200", ""

        def runner(cmd):
            seen["cmd"] = cmd
            return R()
        ok, _ = va.navigate({"open_mode": "docker-exec", "container": ID_A, "open_port": 27180,
                             "docker_path": "docker", "curl_path": "curl"}, "wiki/a b.md", "", runner)
        self.assertTrue(ok)
        self.assertEqual(seen["cmd"], ["docker", "exec", ID_A, "curl", "-sS", "-o", "/dev/null", "-w",
                                       "%{http_code}", "--max-time", "4",
                                       "http://127.0.0.1:27180/open/wiki%2Fa%20b.md"])

    def test_navigate_https_adds_k_only_for_https(self):
        seen = []

        class R:
            returncode, stdout, stderr = 0, "200", ""
        base = {"open_mode": "docker-exec", "container": ID_A, "open_port": 27124}
        va.navigate(dict(base, open_scheme="https"), "a.md", "", lambda c: seen.append(c) or R())
        va.navigate(base, "a.md", "", lambda c: seen.append(c) or R())
        self.assertIn("-k", seen[0])
        self.assertEqual(seen[0][-1], "https://127.0.0.1:27124/open/a.md")
        self.assertNotIn("-k", seen[1])
        self.assertEqual(seen[1][-1], "http://127.0.0.1:27124/open/a.md")

    def test_line_breaks_never_reach_a_signature(self):
        with self.assertRaises(ValueError):
            va.build_go_link({"link_ttl_s": 0, "self_url": "http://a", "_dir": "/nonexistent",
                              "link_secret_file": "x", "token_file": "y"}, "v", "a\nb")
        for q in ({"v": ["v"], "n": ["a\nb"], "s": ["x"]}, {"v": ["v\r"], "n": ["a"], "s": ["x"]},
                  {"v": ["v"], "n": ["a"], "h": ["b\n"], "s": ["x"]}):
            ok, code, *_ = va.verify_go({"link_ttl_s": 0, "_dir": "/nonexistent", "vaults": {},
                                         "link_secret_file": "x", "token_file": "y"}, q)
            self.assertEqual((ok, code), (False, 400))

    def test_legacy_links_keep_their_signature(self):
        # Links already in chat histories must stay valid: the legacy format is unchanged.
        self.assertEqual(va._canonical("v", "wiki/a.md", "Intro", 0), "v\nwiki/a.md\nIntro\n0")

    def test_canonical_v2_is_unambiguous_and_separate_from_legacy(self):
        h = {"rest": "http://192.0.2.1:27180"}
        # The legacy newline join collides here: note "a\nb" vs note "a" + anchor "b\n".
        self.assertEqual(va._canonical("v", "a\nb", "", 0), va._canonical("v", "a", "b\n", 0))
        self.assertNotEqual(va._canonical("v", "a\nb", "", 0, h), va._canonical("v", "a", "b\n", 0, h))
        self.assertNotEqual(va._canonical("v", "a", "", 0, h), va._canonical("v", "a", "", 0))


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
