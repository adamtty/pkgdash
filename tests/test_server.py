"""Tests for server.py and demo.py. Run with: /usr/bin/python3 -m unittest discover -s tests -v

Every server here runs from this checkout with HOME pointed at a temporary folder and its own port,
so nothing touches a real install. Setup is never finished in these servers, so no scan or update
ever runs (the scheduler waits for setup), and no test asks for one.
"""
import json
import os
import re
import shutil
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
                     '{"dependencies": {"x": 5}}', '{"packages": {"node_modules/x": {"version": 3}}}', deep, "not json"):
            self.assertEqual(server.lock_deps("package-lock.json", text), [], text[:40])

    def test_real_lockfiles_still_parse(self):
        corpus = os.path.join(HERE, "fuzz-corpus", "lockfiles")
        def deps(seed, fname):
            with open(os.path.join(corpus, seed)) as f:
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
