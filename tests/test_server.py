"""Tests for server.py and demo.py. Run with: /usr/bin/python3 -m unittest discover -s tests -v

Every server here runs from this checkout with HOME pointed at a temporary folder and its own port,
so nothing touches a real install. Setup is never finished in these servers, so no scan or update
ever runs (the scheduler waits for setup), and no test asks for one.
"""
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PORT, DEMO_PORT = 17979, 17980

# server.py builds its state at import time, under HOME: give it a throwaway one first
UNIT_HOME = tempfile.mkdtemp(prefix="pkgdash-unit-")
os.environ["HOME"] = UNIT_HOME
sys.path.insert(0, ROOT)
import server  # noqa: E402


def start(script, port, home, extra_env=None):
    env = dict(os.environ, HOME=home, PKGDASH_PORT=str(port), **(extra_env or {}))
    log = open(os.path.join(home, "out.log"), "w+")
    proc = subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, script)], env=env, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/api/state" % port, timeout=1).read()
            return proc, log
        except (OSError, ValueError):
            time.sleep(0.1)
    log.seek(0)
    proc.kill()
    raise AssertionError("%s didn't start:\n%s" % (script, log.read()))


class ProjectsRoot(unittest.TestCase):
    def test_inside_home_is_kept(self):
        for given, want in (("~/Documents", "~/Documents"), ("~/code/../Developer", "~/Developer"),
                            ("~/a/./b/", "~/a/b"), (os.path.join(UNIT_HOME, "src"), "~/src")):
            self.assertEqual(server.clean_projects_root(given), want, given)

    def test_outside_home_or_library_is_refused(self):
        for bad in ("/etc", "~", "~/", "~/..", "~/../x", "~/Library", "~/Library/Keychains", "", "   ",
                    "relative/path", "~/a\0b", None, 7, ["~/x"]):
            self.assertIsNone(server.clean_projects_root(bad), repr(bad))


class LockfileParsing(unittest.TestCase):
    """Lockfiles come from any project, so a hostile one must be skipped, never crash the scan."""

    def test_hostile_package_locks_parse_to_nothing(self):
        deep = '{"dependencies": ' + '{"x": {"version": "1", "dependencies": ' * 5000 + "{}" + "}}" * 5000 + "}"
        for text in ("[]", '{"packages": {"node_modules/x": "1.0.0"}}', '{"packages": ["x"]}',
                     '{"dependencies": {"x": 5}}', '{"packages": {"node_modules/x": {"version": 3}}}', deep, "not json",
                     # found by Atheris: keys that name no package
                     '{"packages": {"node_modules/": {"version": "1.0.0"}}}', '{"dependencies": {"": {"version": "1"}}}'):
            self.assertEqual(server.lock_deps("package-lock.json", text), [], text[:40])

    def test_real_lockfiles_still_parse(self):
        corpus = os.path.join(HERE, "fuzz-corpus", "lockfiles")
        def deps(seed, fname):
            with open(os.path.join(corpus, seed + ".seed")) as f:
                return server.lock_deps(fname, f.read())
        self.assertEqual(deps("package-lock-v3.json", "package-lock.json"),
                         [("@scope/pkg", "2.1.0"), ("b", "0.1.0"), ("left-pad", "1.3.0")])
        self.assertEqual(deps("package-lock-v1.json", "package-lock.json"),
                         [("debug", "2.6.9"), ("express", "4.18.2"), ("lodash", "4.17.21"), ("ms", "2.0.0")])
        self.assertEqual(deps("yarn-v1.lock", "yarn.lock"), [("@babel/core", "7.23.2"), ("lodash", "4.17.21")])
        self.assertEqual(deps("requirements.txt", "requirements.txt"), [("requests", "2.31.0"), ("urllib3", "2.0.7")])
        self.assertEqual(deps("Cargo.lock", "Cargo.lock"), [("serde", "1.0.190")])
        self.assertEqual(deps("uv.lock", "uv.lock"), [("requests", "2.31.0")])
        self.assertEqual(deps("poetry.lock", "poetry.lock"), [("click", "8.1.7")])
        # registry gems only (not GIT/PATH ones), platform builds folded into one version
        self.assertEqual(deps("Gemfile.lock", "Gemfile.lock"),
                         [("nokogiri", "1.16.0"), ("racc", "1.7.3"), ("rails", "7.1.3"), ("rspec-core", "3.13.0.pre.beta1")])

    def test_hostile_gemfile_locks_parse_to_nothing(self):
        for text in ("", "GEM\n  specs:\n    (1.0)\n", "GEM\n    -rf (1.0)\n", "GEM\n    x (../../etc)\n",
                     "GEM\n    x (1.0:evil)\n", "GIT\n    x (1.0)\n", "GEM\n      deep (1.0)\n", "GEM\n    x ()\n"):
            self.assertEqual(server.lock_deps("Gemfile.lock", text), [], repr(text))
        self.assertEqual(server.lock_deps("Gemfile.lock", "GEM\r\n    x (1.0)\r\n"), [("x", "1.0")])


class Gems(unittest.TestCase):
    """The ruby gems manager, with a stand-in for running ruby and gem."""

    class Job:
        only, force, id = None, False, "t"

        def __init__(self, outputs):
            self.outputs, self.ran, self.logged = outputs, [], []

        def log(self, text):
            self.logged.append(text)

        def run(self, cmd, cwd=None, timeout=0, quiet=False):
            self.ran.append([str(c) for c in cmd])
            return self.outputs["ruby" if cmd[1] == "-e" else "outdated"]

        def stream(self, cmd, cwd=None, timeout=0):
            self.ran.append([str(c) for c in cmd])
            return 0

    GEMS = json.dumps([["json", "2.18.0", ["2.18.0", "2.9.1"], "default"], ["rake", "13.3.0", ["13.3.0"], "bundled"],
                       ["rubocop", "1.80.0", ["1.80.0"], "gem"], ["tidy", "1.0", ["1.0"], "gem"]])
    OUTDATED = "json (2.18.0 < 2.19.9)\nrake (13.3.0 < 13.4.2)\nrubocop (1.80.0 < 1.81.2)\n"

    def osv(self, url, body=None, timeout=0):
        """OSV's querybatch, knowing one advisory: in json 2.18.0."""
        self.osv_asked.append([q["package"]["name"] for q in body["queries"]])
        return {"results": [{"vulns": [{"id": "GHSA-3m6g-2423-7cp3"}]} if q["package"]["name"] == "json" else {}
                            for q in body["queries"]]}

    def setUp(self):
        self.osv_asked = []
        self.orig_http = server.http_json
        server.http_json = self.osv
        self.addCleanup(setattr, server, "http_json", self.orig_http)
        self.gem = server.Gem()
        self.gem.ruby = lambda: "/opt/homebrew/bin/ruby"
        self.gem.gem = lambda: "/opt/homebrew/Cellar/ruby/4.0.7/bin/gem"
        self.job = self.Job({"ruby": (0, self.GEMS), "outdated": (0, self.OUTDATED)})

    def test_scan(self):
        rows = {r["name"]: r for r in self.gem.scan(self.job)}
        self.assertEqual(sorted(rows), ["json", "rake", "rubocop", "tidy"])
        self.assertEqual((rows["json"]["latest"], rows["rubocop"]["latest"], rows["tidy"]["latest"]), ("2.19.9", "1.81.2", None))
        self.assertTrue(rows["rubocop"]["outdated"] and not rows["tidy"]["outdated"])
        # Ruby's own gems: json has a known vulnerability so it counts; rake has none, so it's only `newer`
        self.assertEqual(self.osv_asked, [["json", "rake"]])  # gems you installed aren't asked about
        self.assertTrue(rows["json"]["outdated"])
        self.assertEqual((rows["rake"]["outdated"], rows["rake"].get("newer"), rows["rake"]["latest"]), (False, True, "13.4.2"))
        self.assertIn("default gem", rows["json"]["note"])
        self.assertIn("also installed: 2.9.1", rows["json"]["note"])

    def test_osv_unreachable_counts_rubys_own_gems_as_outdated(self):
        def down(*a, **k):
            raise OSError("no network")
        server.http_json = down
        rows = {r["name"]: r for r in self.gem.scan(self.job)}
        self.assertTrue(rows["rake"]["outdated"] and not rows["rake"].get("newer"))

    def test_every_installed_version_is_checked(self):
        self.assertIn(("json", "2.9.1", "json"), self.gem.dep_tree(self.job))

    def test_ruby_that_fails_is_an_error_not_an_empty_list(self):
        self.job.outputs["ruby"] = (1, "ruby: cannot load such file")
        with self.assertRaises(RuntimeError):
            self.gem.gems(self.job)

    def test_macos_ruby_is_left_alone(self):
        orig = server.which
        server.which = lambda name: "/usr/bin/ruby"
        try:
            self.assertFalse(server.Gem().available())
        finally:
            server.which = orig

    def installs(self, only=None):
        inv = {("gem", r["name"]): r for r in self.gem.scan(self.job)}
        inv[("gem", "rubocop")]["latest"] = "1.81.2 --source=https://evil.example"
        orig_inv, orig_gate = server.inv_pkgs, server.Manager.gate
        server.inv_pkgs = lambda mid: inv
        server.Manager.gate = lambda self, job: {}
        try:
            self.job.ran.clear()
            self.gem.update(self.job, only)
        finally:
            server.inv_pkgs, server.Manager.gate = orig_inv, orig_gate
        return [c[2:5] for c in self.job.ran if "install" in c]

    def test_update_installs_the_scanned_version(self):
        self.assertEqual(self.installs(), [["json", "--version", "2.19.9"]])  # rake is only `newer`; rubocop's odd "version" is skipped
        cmd = [c for c in self.job.ran if "install" in c][0]
        self.assertEqual(cmd, ["/opt/homebrew/Cellar/ruby/4.0.7/bin/gem", "install", "json", "--version", "2.19.9",
                               "--conservative", "--no-document"])

    def test_a_newer_gem_updates_when_asked_for_by_name(self):
        self.assertEqual(self.installs(("gem", "rake")), [["rake", "--version", "13.4.2"]])

    def test_newer_gems_still_wait_out_the_cooldown(self):
        p = {"newer": True, "outdated": False, "latest": "13.4.2", "released": server.now() - 3600}
        self.addCleanup(server.store["settings"].__setitem__, "cooldown_days", server.store["settings"].get("cooldown_days"))
        server.store["settings"]["cooldown_days"] = 5
        self.assertGreater(server.cooldown_left(p), 0)


class DockerGems(unittest.TestCase):
    def test_gems_in_an_image(self):
        files = {"usr/local/bundle/specifications/nokogiri-1.16.0-x86_64-linux.gemspec": b"",
                 "usr/local/lib/ruby/gems/3.3.0/specifications/default/json-2.7.1.gemspec": b"",
                 "usr/local/bundle/specifications/net-http-0.4.1.gemspec": b"",
                 "usr/local/bundle/specifications/not a gemspec.gemspec": b""}
        self.assertTrue(all(server.DOCKER_WANT.match(p) for p in files))
        self.assertFalse(server.DOCKER_WANT.match("app/mygem.gemspec"))
        _, pkgs = server.image_packages(files)
        self.assertEqual(pkgs, [("RubyGems", "json", "2.7.1"), ("RubyGems", "net-http", "0.4.1"),
                                ("RubyGems", "nokogiri", "1.16.0")])


class Migration(unittest.TestCase):
    def setUp(self):
        self.state = server.STATE_DIR / "state.json"
        self.saved = self.state.read_text() if self.state.exists() else None

    def tearDown(self):
        if self.saved is None:
            self.state.unlink(missing_ok=True)
        else:
            self.state.write_text(self.saved)

    def test_existing_install_counts_as_set_up(self):
        self.state.write_text(json.dumps({"settings": {"scan_every_hours": 3}}))
        st = server.Store()
        self.assertTrue(st["settings"]["setup_done"])
        self.assertEqual(st["settings"]["scan_every_hours"], 3)

    def test_fresh_install_shows_setup(self):
        self.state.unlink(missing_ok=True)
        self.assertFalse(server.Store()["settings"]["setup_done"])


class Service(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.mkdtemp(prefix="pkgdash-e2e-")
        cls.proc, cls.log = start("server.py", PORT, cls.home)
        page = urllib.request.urlopen("http://127.0.0.1:%d/" % PORT).read().decode()
        cls.token = re.search(r'const TOKEN = "([^"]+)"', page).group(1)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(10)
        cls.log.close()
        shutil.rmtree(cls.home, ignore_errors=True)

    def req(self, method, path, body=None, headers=None, token=True):
        h = {"Host": "127.0.0.1:%d" % PORT, "Content-Type": "application/json"}
        if token:
            h["X-Pkgdash-Token"] = self.token
        h.update(headers or {})
        r = urllib.request.Request("http://127.0.0.1:%d%s" % (PORT, path), method=method, headers=h,
                                   data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def state(self):
        return self.req("GET", "/api/state", token=False)[1]

    # -- who may talk to it --

    def test_foreign_host_is_refused(self):
        for host in ("evil.example:%d" % PORT, "127.0.0.1.evil.example", ""):
            self.assertEqual(self.req("GET", "/api/state", headers={"Host": host})[0], 403, host)

    def test_post_needs_the_token(self):
        self.assertEqual(self.req("POST", "/api/settings", {"notify": False}, token=False)[0], 403)
        self.assertEqual(self.req("POST", "/api/settings", {"notify": False}, headers={"X-Pkgdash-Token": "x"})[0], 403)

    def test_foreign_origin_is_refused(self):
        code, _ = self.req("POST", "/api/settings", {"notify": False}, headers={"Origin": "https://evil.example"})
        self.assertEqual(code, 403)

    def test_lan_mode_is_gone(self):
        self.assertEqual(self.req("POST", "/api/lan", {"on": True})[0], 404)
        self.assertNotIn("lan", self.state())

    # -- setup --

    def test_nothing_runs_before_setup(self):
        s = self.state()
        self.assertFalse(s["settings"]["setup_done"])
        self.assertEqual(s["jobs"], [])

    def test_settings_validation(self):
        code, s = self.req("POST", "/api/settings", {"projects_root": "~/code/../Developer", "scan_every_hours": "evil",
                                                     "notify": [1], "disabled_managers": ["docker", "bogus"]})
        self.assertEqual(code, 200)
        self.assertEqual(s["projects_root"], "~/Developer")
        self.assertEqual(s["scan_every_hours"], 6)
        self.assertIs(s["notify"], True)
        self.assertEqual(s["disabled_managers"], ["docker"])
        for bad in ("/etc", "~", "~/Library/Keychains", "~/../x", 3):
            self.assertEqual(self.req("POST", "/api/settings", {"projects_root": bad})[0], 400, bad)
        self.assertEqual(self.state()["settings"]["projects_root"], "~/Developer")
        self.req("POST", "/api/settings", {"disabled_managers": [], "projects_root": "~/Documents"})

    def test_turned_off_managers_disappear_and_cant_run(self):
        self.req("POST", "/api/settings", {"disabled_managers": ["cargo"]})
        try:
            s = self.state()
            self.assertNotIn("cargo", [m["id"] for m in s["managers"]])
            self.assertIn({"id": "cargo", "enabled": False}, [{k: m[k] for k in ("id", "enabled")} for m in s["manager_choices"]])
            self.assertEqual(self.req("POST", "/api/run", {"manager": "cargo", "action": "scan"})[0], 400)
            self.assertNotIn("cargo", self.req("GET", "/api/inventory", token=False)[1])
        finally:
            self.req("POST", "/api/settings", {"disabled_managers": []})

    def test_bad_socket_tokens_never_reach_the_keychain(self):
        for bad in ("x; rm -rf ~", "short", "a b c d e f g h i j k l m n o p", "x" * 300, "tok\nadd-generic-password"):
            self.assertEqual(self.req("POST", "/api/socket", {"token": bad})[0], 400, repr(bad))

    def test_advisory_ids_are_validated(self):
        for bad in ("../../etc/passwd", "MAL-1/../x", "", "<script>"):
            self.assertEqual(self.req("GET", "/api/advisory?id=" + urllib.request.quote(bad), token=False)[0], 400, bad)


class Trust(unittest.TestCase):
    """Requests to registries, OSV and Socket trust the default roots minus eMudhra's."""

    def test_context_has_roots_but_no_emudhra(self):
        server.tls_context.cache_clear()
        ctx = server.tls_context()
        names = [str(c.get("subject")) for c in ctx.get_ca_certs()]
        self.assertGreater(len(names), 100)
        self.assertEqual([n for n in names if "eMudhra" in n or "emSign" in n], [])
        self.assertTrue(ctx.check_hostname)

    def test_only_emudhra_roots_are_dropped(self):
        pems = server.PEM_RE.findall(server.ca_bundle())
        dropped = [p for p in pems if server.distrusted(p)]
        if not dropped:
            self.skipTest("this machine's default roots have no eMudhra root")
        for pem in dropped:
            self.assertIn(b"emSign", ssl.PEM_cert_to_DER_cert(pem))
        self.assertGreater(len(pems) - len(dropped), 100)

    def test_ssl_cert_file_is_honoured_and_filtered(self):
        pems = server.PEM_RE.findall(server.ca_bundle())
        bundle = os.path.join(UNIT_HOME, "corp.pem")
        with open(bundle, "w") as f:
            f.write("\n".join([next(p for p in pems if not server.distrusted(p))] + [p for p in pems if server.distrusted(p)]))
        os.environ["SSL_CERT_FILE"] = bundle
        server.tls_context.cache_clear()
        try:
            self.assertEqual(len(server.tls_context().get_ca_certs()), 1)
        finally:
            del os.environ["SSL_CERT_FILE"]
            server.tls_context.cache_clear()


class Demo(unittest.TestCase):
    def test_demo_serves_only_made_up_data(self):
        home = tempfile.mkdtemp(prefix="pkgdash-demo-test-")
        proc, log = start("demo.py", DEMO_PORT, home)
        try:
            s = json.loads(urllib.request.urlopen("http://127.0.0.1:%d/api/state" % DEMO_PORT).read())
            self.assertEqual((s["user"], s["host"]), ("alex", "macbook"))
            self.assertTrue(s["settings"]["setup_done"])
            self.assertGreater(s["totals"]["packages"], 0)
            self.assertNotIn(os.path.expanduser("~"), json.dumps(s))
        finally:
            proc.terminate()
            proc.wait(10)
            log.close()
            shutil.rmtree(home, ignore_errors=True)


def tearDownModule():
    shutil.rmtree(UNIT_HOME, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
