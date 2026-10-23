#!/usr/bin/python3 -I
"""pkgdash: one dashboard for every package manager on this Mac.

Inventories, CVE audits and updates for uv tools, npm globals, Homebrew,
pip-in-Homebrew-Python, Go binaries, Cargo crates and stray binaries.
Runs as a LaunchAgent under /usr/bin/python3 (stdlib only) on 127.0.0.1.
"""
import calendar
import concurrent.futures
import functools
import getpass
import hashlib
import json
import os
import queue
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

HOME = Path.home()
APP_DIR = Path(__file__).resolve().parent
STATE_DIR = HOME / ".local/share/pkgdash"
LOG_DIR = STATE_DIR / "logs"
PROJECTS_DIR = STATE_DIR / "projects"  # copies of the lockfiles it sends
HOST = "127.0.0.1"
PORT = int(os.environ.get("PKGDASH_PORT", "7878"))
TOKEN = secrets.token_urlsafe(24)
STARTED = time.time()

PATH = ":".join([
    str(HOME / ".local/bin"),
    str(HOME / ".local/share/fnm/aliases/default/bin"),
    "/opt/homebrew/bin", "/opt/homebrew/sbin",
    str(HOME / "go/bin"), str(HOME / ".cargo/bin"),
    "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
])
ENV = dict(
    os.environ, PATH=PATH, HOME=str(HOME),
    HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ENV_HINTS="1",
    NO_COLOR="1", FORCE_COLOR="0", TERM="dumb",
    npm_config_fund="false", npm_config_update_notifier="false",
)

DEFAULT_SETTINGS = {
    "scan_every_hours": 6,       # inventory + outdated + new-package detection
    "audit_every_hours": 24,     # CVE audits
    "update_every_hours": 0,     # 0 = never update automatically
    "notify": True,              # macOS notification for scheduled-run events
    "npm_major_self_update": False,
    "brew_cleanup": True,
    "brew_skip_running_casks": True,
    "cooldown_days": 5,          # don't install a release until it's this old (hijacked ones get pulled fast)
    "socket_check": True,        # also ask Socket.dev (token in the login Keychain) during malware checks
    "disabled_managers": [],     # turned off on the setup screen: not scanned, audited, updated or shown
    "projects_root": "~/Documents",  # where the menu bar app looks for project lockfiles
    "setup_done": False,         # False = show the first-run setup wizard
}
SOCKET_ITEM = "pkgdash-socket-token"  # login Keychain item (service name) holding the Socket.dev API token

# audit tools pkgdash runs itself: pinned, so a hijacked release of either can't reach us via a scheduled audit
PIP_AUDIT_VERSION = "2.10.1"
GOVULNCHECK_VERSION = "v1.9.0"

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def now():
    return time.time()


def which(name):
    return shutil.which(name, path=PATH)


def norm_sev(s):
    s = (s or "").lower()
    if s == "moderate":
        s = "medium"
    return s if s in SEV_RANK else "unknown"


def pkg(name, version, latest=None, kind="", note=""):
    latest = latest or None
    return {"name": name, "version": version or "-", "latest": latest,
            "outdated": bool(latest and latest != version), "kind": kind, "note": note}


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def parse_iso(s):
    """Epoch from a registry timestamp (all UTC); fractions and offsets ignored."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", str(s or ""))
    return calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")) if m else None


def cooldown_left(p):
    """Seconds until a package's new version is old enough to install (0 = go ahead)."""
    days = float(store["settings"].get("cooldown_days") or 0)
    if days <= 0 or not (p.get("outdated") or p.get("newer")) or not p.get("latest") or not p.get("released"):
        return 0
    return max(0, p["released"] + days * 86400 - now())


def left_text(secs):
    days = secs / 86400
    if days >= 1:
        n = int(-(-days // 1))
        return "%d day%s" % (n, "" if n == 1 else "s")
    n = max(1, int(-(-secs // 3600)))
    return "%d hour%s" % (n, "" if n == 1 else "s")


def cooldown_cutoff():
    return now() - float(store["settings"].get("cooldown_days") or 0) * 86400


def flag_text(fid):
    """How a malware-check hit reads: OSV MAL- ids and Socket's malware verdict are known malware;
    Socket's other blocking alerts (typosquat, protestware, ...) are only flagged."""
    return "known malware (%s)" % fid if fid.startswith("MAL-") or fid == "Socket: malware" else "flagged by " + fid


def inv_pkgs(mid):
    return {(p["kind"], p["name"]): p for p in (store["inventory"].get(mid) or {}).get("packages", [])}


def finding(pkg_name, version, vid, severity, summary, fix, context, aliases=()):
    return {"pkg": pkg_name, "version": version or "", "id": vid,
            "aliases": [a for a in aliases if a != vid][:3],
            "severity": norm_sev(severity), "summary": (summary or "").strip()[:240],
            "fix": fix or "", "context": context}


def iter_json(text):
    dec, i, n = json.JSONDecoder(), 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            return
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            return
        yield obj


def loads(text, default):
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError):  # RecursionError: absurdly nested JSON
        return default


# eMudhra's (emSign) roots are left out of what the registry, OSV and Socket requests trust: in October 2026 the keys of
# 8 of their intermediate CAs turned out to be guessable. Browsers block those intermediates, but macOS's
# /etc/ssl/cert.pem still trusts the roots above them. Dropped by SHA-256, or if the root names eMudhra at all.
EMUDHRA_ROOTS = {
    "40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367",  # emSign Root CA - G1
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",  # emSign ECC Root CA - G3
    "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f",  # emSign Root CA - C1
    "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3",  # emSign ECC Root CA - C3
}
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


def distrusted(pem):
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest() in EMUDHRA_ROOTS or b"eMudhra" in der


def ca_bundle():
    """The roots Python trusts by default, as PEM: $SSL_CERT_FILE, else its default file, else its default folder."""
    paths = ssl.get_default_verify_paths()
    cafile = os.environ.get(paths.openssl_cafile_env) or paths.cafile
    if cafile:
        files = [cafile]
    elif paths.capath and os.path.isdir(paths.capath):
        files = [os.path.join(paths.capath, n) for n in sorted(os.listdir(paths.capath))]
    else:
        files = []
    out = []
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:  # labels in comments can be non-ASCII
                out.append(fh.read())
        except (OSError, ValueError):
            pass
    return "\n".join(out)


@functools.lru_cache(maxsize=None)
def tls_context():
    pems = list(dict.fromkeys(p for p in PEM_RE.findall(ca_bundle()) if not distrusted(p)))  # a folder repeats them
    return ssl.create_default_context(cadata="\n".join(pems)) if pems else ssl.create_default_context()


def http_json(url, body=None, timeout=30, headers=None):
    if not url.startswith("https://"):  # registries and OSV only: never file: or plain http
        raise ValueError("not an https URL: " + url[:80])
    req = urllib.request.Request(  # noqa: S310 - https enforced above
        url, data=json.dumps(body).encode() if body is not None else None,
        headers={"User-Agent": "pkgdash/1.0 (local dashboard)",
                 "Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout, context=tls_context()) as r:  # noqa: S310
        return json.loads(r.read())


def pypi_released(name, version):
    """Upload time of a PyPI release (its first file), if PyPI has it."""
    data = http_json("https://pypi.org/pypi/%s/%s/json" % (quote(name), quote(version)))
    times = [t for t in (parse_iso(u.get("upload_time_iso_8601")) for u in data.get("urls", [])) if t]
    return min(times) if times else None


# ---------------------------------------------------------------- store

class Store:
    def __init__(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.path = STATE_DIR / "state.json"
        self.data = {"inventory": {}, "vulns": {}, "malware": {}, "jobs": [], "events": [],
                     "settings": {}, "schedule": {}}
        existing = self.path.exists()
        if existing:
            self.data.update(loads(self.path.read_text(), {}))
        saved = self.data.get("settings", {})
        if existing and "setup_done" not in saved:  # set up before the setup screen existed
            saved["setup_done"] = True
        self.data["settings"] = {**DEFAULT_SETTINGS, **saved}
        for k in ("reviews", "ai_usage"):  # left over from the removed AI review
            self.data.pop(k, None)
        self.data["settings"].pop("ai_review", None)
        for j in self.data["jobs"]:
            if j["state"] in ("queued", "running"):
                j["state"] = "aborted"
        self.save()

    def __getitem__(self, k):
        return self.data[k]

    def __setitem__(self, k, v):
        self.data[k] = v

    def save(self):
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data))
            os.replace(tmp, self.path)

    def add_event(self, kind, manager, text):
        with self.lock:
            self.data["events"].append({"id": uuid.uuid4().hex[:10], "ts": now(), "kind": kind,
                                        "manager": manager, "text": text, "read": False})
            self.data["events"] = self.data["events"][-300:]


store = Store()


# ---------------------------------------------------------------- jobs

class Job:
    def __init__(self, manager, action, trigger, only=None, force=False):
        self.id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
        self.manager, self.action, self.trigger = manager, action, trigger
        self.only = only  # (kind, name) when updating a single package
        self.force = force  # single package only: install even though it's in its cooldown period
        self.logf = LOG_DIR / (self.id + ".log")
        self.rec = {"id": self.id, "manager": manager, "action": action, "trigger": trigger,
                    "pkg": only[1] if only else None, "kind": only[0] if only else None,
                    "queued": now(), "started": None, "ended": None,
                    "state": "queued", "summary": ""}
        self._lock = threading.Lock()

    def log(self, text):
        if not text:
            return
        with self._lock, open(self.logf, "a") as f:
            f.write(text if text.endswith("\n") else text + "\n")

    def run(self, cmd, cwd=None, timeout=1800, quiet=False):
        """Run and capture stdout (for parsing); stderr goes to the log."""
        self.log("$ " + " ".join(shlex.quote(str(c)) for c in cmd))
        try:
            p = subprocess.run([str(c) for c in cmd], cwd=cwd, env=ENV, capture_output=True,
                               text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            self.log("! command not found: %s" % cmd[0])
            return 127, ""
        except subprocess.TimeoutExpired:
            self.log("! timed out after %ss" % timeout)
            return 124, ""
        if not quiet:
            self.log(p.stdout[-6000:])
        self.log(p.stderr[-4000:])
        return p.returncode, p.stdout

    def stream(self, cmd, cwd=None, timeout=3600):
        """Run with output streamed live into the log (for updates)."""
        self.log("$ " + " ".join(shlex.quote(str(c)) for c in cmd))
        try:
            p = subprocess.Popen([str(c) for c in cmd], cwd=cwd, env=ENV, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, bufsize=1)
        except FileNotFoundError:
            self.log("! command not found: %s" % cmd[0])
            return 127
        timer = threading.Timer(timeout, p.kill)
        timer.start()
        try:
            for line in p.stdout:
                self.log(line.rstrip("\n"))
        finally:
            timer.cancel()
        return p.wait()


class Runner:
    def __init__(self):
        self.q = queue.Queue()
        self.jobs = {}
        threading.Thread(target=self._worker, daemon=True).start()

    def enqueue(self, manager_id, action, trigger="manual", only=None, force=False):
        targets = [m for m in MANAGERS if m.available() and enabled(m) and action in m.actions
                   and (manager_id == "all" or m.id == manager_id)
                   and not (action == "update" and m.separate and not only)]  # projects: one at a time
        if action == "update":
            targets = [m for m in targets if not m.hold]
        queued = []
        with store.lock:
            busy = {(j["manager"], j["action"], j.get("kind"), j.get("pkg")) for j in store["jobs"]
                    if j["state"] in ("queued", "running")}
            for m in targets:
                if (m.id, action) + (only or (None, None)) in busy:
                    continue
                job = Job(m.id, action, trigger, only, force)
                self.jobs[job.id] = job
                store["jobs"].append(job.rec)
                queued.append(job.id)
                self.q.put(job)
            store["jobs"] = store["jobs"][-300:]
            store.save()
        return queued

    def _worker(self):
        while True:
            job = self.q.get()
            m = MANAGER_BY_ID[job.manager]
            job.rec.update(state="running", started=now())
            store.save()
            try:
                job.rec["summary"] = getattr(self, "_" + job.action)(m, job) or ""
                job.rec["state"] = "ok"
            except Exception as e:  # keep the service alive whatever a manager does
                job.log(traceback.format_exc())
                job.rec.update(state="failed", summary=str(e)[:200])
                store.add_event("job_failed", m.id, "%s %s failed: %s" % (m.label, job.action, e))
            job.rec["ended"] = now()
            store.save()
            self.jobs.pop(job.id, None)
            self._notify_if_scheduled(job)

    def _scan(self, m, job):
        pkgs = m.scan(job)
        prev = store["inventory"].get(m.id)
        # first_seen: 0 = present at the baseline scan, else when a scan first found it
        seen = {(p["kind"], p["name"]): p.get("first_seen", 0) for p in prev["packages"]} if prev else {}
        old_pk = {(p["kind"], p["name"]): p for p in prev["packages"]} if prev else {}
        for p in pkgs:
            p["first_seen"] = seen.get((p["kind"], p["name"]), now() if prev else 0)
            old = old_pk.get((p["kind"], p["name"])) or {}
            if p["latest"]:
                self._release_date(m, job, p, old)
            # carried over in case OSV can't be reached this time
            if m.osv_eco:
                p["malware"] = old.get("malware") if old.get("version") == p["version"] else None
            p["blocked"] = old.get("blocked") if old.get("latest") == p["latest"] else None
            p["socket"] = old.get("socket") if old.get("latest") == p["latest"] else None
        self._malware_check(m, job, pkgs, installed=True)
        if prev is not None:
            old = {(p["kind"], p["name"]) for p in prev["packages"]}
            new = {(p["kind"], p["name"]) for p in pkgs}
            added = sorted(n for k, n in new - old)
            removed = sorted(n for k, n in old - new)
            if added:
                store.add_event("new_pkg", m.id, "%s: %d new — %s" % (m.label, len(added), ", ".join(added[:12])))
            if removed:
                store.add_event("removed_pkg", m.id, "%s: %d removed — %s" % (m.label, len(removed), ", ".join(removed[:12])))
        store["inventory"][m.id] = {"scanned_at": now(), "packages": pkgs}
        outd = sum(p["outdated"] for p in pkgs)
        return "%d packages, %d outdated" % (len(pkgs), outd)

    def _audit(self, m, job):
        fs = m.audit(job)
        seen, uniq = set(), []
        for f in fs:
            k = (f["context"], f["pkg"], f["id"])
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        uniq.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["context"], f["pkg"]))
        prev = store["vulns"].get(m.id)
        if prev is not None:
            old = {(f["context"], f["pkg"], f["id"]) for f in prev["findings"]}
            fresh = [f for f in uniq if (f["context"], f["pkg"], f["id"]) not in old]
            if fresh:
                store.add_event("new_vuln", m.id, "%s: %d new vulnerabilities — %s" % (
                    m.label, len(fresh), ", ".join(sorted({f["pkg"] for f in fresh})[:10])))
        store["vulns"][m.id] = {"audited_at": now(), "findings": uniq}
        hi = sum(SEV_RANK[f["severity"]] >= 3 for f in uniq)
        return "%d findings (%d high/critical)" % (len(uniq), hi)

    @staticmethod
    def _release_date(m, job, p, old):
        """When the new version came out, for the cooldown: the registry's date, else when we first saw it."""
        same = old and old.get("latest") == p["latest"]
        p["latest_seen"] = old["latest_seen"] if same and old.get("latest_seen") else now()
        if p.get("released"):
            p["released_src"] = "registry"
            return
        if same and old.get("released_src") == "registry":
            p["released"], p["released_src"] = old["released"], "registry"
            return
        try:
            p["released"] = m.released(job, p)
        except Exception as e:
            job.log("! release date lookup failed for %s: %s" % (p["name"], e))
        p["released_src"] = "registry" if p.get("released") else "seen"
        p["released"] = p.get("released") or p["latest_seen"]

    def _malware_check(self, m, job, pkgs, installed):
        """Ask OSV's malicious-packages list about everything installed (deps too) and every pending version."""
        if not m.osv_eco:
            return
        q = []
        if installed:
            try:
                q = [(n, v, ctx, "installed") for n, v, ctx in m.dep_tree(job)]
            except Exception as e:
                job.log("! couldn't list installed packages for the malware check: %s" % e)
        q += [(m.osv_name(p), p["latest"], p["name"], "latest") for p in pkgs if p.get("latest")]
        if not q:
            return
        job.log("# malware check: %d package versions against OSV" % len(q))
        hits, ok = [], False
        try:
            hits, ok = osv_malware(m.osv_eco, q), True
        except Exception as e:  # never block on OSV being down; say so in the log
            job.log("! OSV malware check failed: %s" % e)
        try:
            ok = self._socket_check(m, job, pkgs, q, hits, installed) or ok
        except Exception as e:
            job.log("! Socket check failed: %s" % e)
        if not ok:
            return
        blocked = {h["context"]: h["id"] for h in hits if h["where"] == "latest"}
        bad = {}
        for h in hits:
            if h["where"] == "installed":
                bad.setdefault(h["context"], h["id"])
        for p in pkgs:
            p["blocked"] = blocked.get(p["name"])
            if installed:
                p["malware"] = bad.get(p["name"])
        prev = store["malware"].get(m.id) or {}
        if not installed:  # pre-update check only covers these pending versions; keep everything else
            names = {p["name"] for p in pkgs}
            hits += [h for h in prev.get("hits", []) if h["where"] == "installed" or h["context"] not in names]
        record_flags(m, job, hits)

    @staticmethod
    def _socket_check(m, job, pkgs, q, hits, installed):
        """Add Socket's blocking alerts to hits, and note on each pending version what Socket warns about
        or what it does that the installed version didn't (install scripts, network access, ...)."""
        # installed versions are re-asked every few days (OSV still checks them every scan); pending ones
        # every scan and right before an update. Free plan: 500 quota, 100 per lookup, refilling over about an hour
        fresh = 6 * 3600 if installed else 3600
        items = [(n, v, 3 * 86400 if where == "installed" else fresh) for n, v, _, where in q]
        items += [(m.osv_name(p), p["version"], 3 * 86400) for p in pkgs if p.get("outdated") and p.get("latest")]
        sk = socket_alerts(job, m.osv_eco, items)
        if sk is None:
            return False
        have = {(h["id"], h["pkg"], h["version"], h["context"], h["where"]) for h in hits}
        for n, v, ctx, where in q:
            for typ, _, action in sk.get((n, v)) or []:
                fid = "Socket: " + SOCKET_LABEL.get(typ, typ)
                if action == "error" and (fid, n, v, ctx, where) not in have:
                    have.add((fid, n, v, ctx, where))
                    hits.append({"id": fid, "pkg": n, "version": v, "context": ctx, "where": where})
        for p in pkgs:
            if not (p.get("outdated") and p.get("latest")):
                p["socket"] = None
                continue
            new, cur = sk.get((m.osv_name(p), p["latest"])), sk.get((m.osv_name(p), p["version"]))
            if new is None:
                p["socket"] = {"unscanned": True}
                continue
            before = {t for t, _, _ in cur or []}
            added = sorted({SOCKET_LABEL[t] for t, _, _ in new if t in SOCKET_LABEL and t not in before}) if cur is not None else []
            warn = sorted({SOCKET_LABEL.get(t, t) for t, _, a in new if a == "warn"} - set(added))
            p["socket"] = {"new": added, "warn": warn}
        job.log("# Socket: %d package versions looked up" % len(sk))
        return True

    def _update(self, m, job):
        if m.osv_eco:  # re-check right before installing, in case a version was flagged since the last scan
            with store.lock:
                pkgs = (store["inventory"].get(m.id) or {}).get("packages", [])
                pending = [p for p in pkgs if p.get("latest") and (not job.only or (p["kind"], p["name"]) == job.only)]
            self._malware_check(m, job, pending, installed=False)
            store.save()
        try:
            summary = m.update(job, job.only)
        finally:  # re-scan even after a partial failure so the tables show what did change
            job.log("\n# re-scanning after update")
            scanned = self._scan(m, job)
        return (summary or "updated") + " · " + scanned

    def _notify_if_scheduled(self, job):
        if job.trigger != "schedule" or not store["settings"].get("notify"):
            return
        recent = [e for e in store["events"] if e["manager"] == job.manager
                  and e["ts"] >= (job.rec["started"] or 0) and e["kind"] in ("new_pkg", "new_vuln", "job_failed")]
        for e in recent:
            notify("pkgdash", e["text"])


def notify(title, text):
    """A macOS notification. The text (package names etc.) goes in as an argument, never into the script."""
    subprocess.run(["/usr/bin/osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                    "-e", "end run", "--", title, text[:180]], env=ENV, capture_output=True)


# ---------------------------------------------------------------- shared audit helpers

def record_flags(m, job, hits):
    """Store a manager's malware-check hits; inbox event + notification for each one not seen before."""
    prev = store["malware"].get(m.id) or {}
    old = {(h["where"], h["pkg"], h["version"], h["context"]) for h in prev.get("hits", [])}
    store["malware"][m.id] = {"checked_at": now(), "hits": hits}
    for h in hits:
        if (h["where"], h["pkg"], h["version"], h["context"]) in old:
            continue
        text = ("%s: installed package is %s — %s %s (in %s)" if h["where"] == "installed"
                else "%s: update blocked, %s — %s %s")
        args = (m.label, flag_text(h["id"]), h["pkg"], h["version"], h["context"]) if h["where"] == "installed" \
            else (m.label, flag_text(h["id"]), h["pkg"], h["version"])
        store.add_event("malware", m.id, text % args)
        job.log("!!! " + text % args)
        if store["settings"].get("notify"):
            notify("pkgdash: malware", text % args)


def pip_audit(job, reqs, context):
    if not reqs:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(reqs) + "\n")
        path = f.name
    try:
        # pinned: audits run unattended, so the audit tools themselves don't get pulled at @latest
        _, out = job.run(["uvx", "-q", "pip-audit==%s" % PIP_AUDIT_VERSION, "-r", path, "--no-deps", "--disable-pip",
                          "--progress-spinner", "off", "-f", "json"], quiet=True, timeout=900)
    finally:
        os.unlink(path)
    data = loads(out, None)
    if data is None:
        raise RuntimeError("pip-audit gave no JSON for %s" % context)
    res = []
    for d in data.get("dependencies", []):
        for v in d.get("vulns", []):
            fixes = v.get("fix_versions") or []
            res.append(finding(d["name"], d.get("version"), v["id"], "unknown",
                               v.get("description", ""), ", ".join(fixes[:2]) or "none",
                               context, v.get("aliases", [])))
    job.log("  %s: %d findings" % (context, len(res)))
    return res


def osv_malware(eco, queries):
    """MAL- entries (OpenSSF malicious-packages, via OSV) for [(name, version, context, where)]."""
    hits, seen = [], set()
    for i in range(0, len(queries), 1000):  # querybatch takes up to 1000 at a time
        chunk = queries[i:i + 1000]
        data = http_json("https://api.osv.dev/v1/querybatch", {"queries": [
            {"package": {"name": n, "ecosystem": eco}, "version": v} for n, v, _, _ in chunk]}, timeout=90)
        for (n, v, ctx, where), r in zip(chunk, data.get("results", [])):
            for vuln in r.get("vulns") or []:
                key = (vuln["id"], n, v, ctx, where)
                if vuln["id"].startswith("MAL-") and key not in seen:
                    seen.add(key)
                    hits.append({"id": vuln["id"], "pkg": n, "version": v, "context": ctx, "where": where})
    return hits


SOCKET_TYPE = {"PyPI": "pypi", "npm": "npm", "crates.io": "cargo"}  # Socket's free plan covers these
# alert types worth showing when a new version starts doing them (Socket marks most as "ignore")
SOCKET_LABEL = {
    "malware": "malware", "gptMalware": "AI-flagged malware", "didYouMean": "possible typosquat",
    "troll": "troll package", "protestware": "protestware", "installScripts": "install script",
    "networkAccess": "network access", "shellAccess": "shell access", "usesEval": "eval",
    "obfuscatedFile": "obfuscated code", "obfuscatedRequire": "obfuscated require",
    "unstableOwnership": "maintainer change", "newAuthor": "new publisher", "gitDependency": "git dependency",
    "httpDependency": "http dependency", "telemetry": "telemetry", "manifestConfusion": "manifest mismatch",
    "suspiciousStarActivity": "suspicious stars", "gptSecurity": "AI-flagged risk", "gptAnomaly": "AI-flagged anomaly",
}
# PyPI answers once per wheel; only the ones a Mac would install count
SOCKET_RELEASE = re.compile(r"^$|tar-gz|zip|none-any|macosx|universal2")
_socket_lock = threading.Lock()


def socket_purl(t, name, version):
    if t == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return "pkg:%s/%s@%s" % (t, quote(name, safe="/"), version)


def socket_api(token, path, body=None, timeout=30):
    req = urllib.request.Request(
        "https://api.socket.dev/v0/" + path, data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + token, "User-Agent": "pkgdash/1.0 (local dashboard)",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout, context=tls_context()) as r:  # noqa: S310 - fixed https://api.socket.dev/ prefix
        return r.read().decode()


def socket_token():
    """The Socket API token from the login Keychain (never stored by pkgdash); None = Socket check off."""
    if not store["settings"].get("socket_check"):
        return None
    return keychain_socket_token()


def keychain_socket_token():
    p = subprocess.run(["/usr/bin/security", "find-generic-password", "-a", getpass.getuser(), "-s", SOCKET_ITEM, "-w"],
                       capture_output=True, text=True, timeout=20)
    return p.stdout.strip() or None


SOCKET_TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]{16,256}")


def save_socket_token(token):
    """Into the login Keychain through `security -i` on stdin, so the token never shows up in `ps`."""
    user = getpass.getuser()
    if not SOCKET_TOKEN_RE.fullmatch(token) or not re.fullmatch(r"[A-Za-z0-9._-]+", user):
        raise ValueError("unexpected characters")
    p = subprocess.run(["/usr/bin/security", "-i"], input="add-generic-password -U -a %s -s %s -w %s\n" % (user, SOCKET_ITEM, token),
                       capture_output=True, text=True, timeout=20)
    if keychain_socket_token() != token:
        raise OSError("couldn't save it to the Keychain: " + (p.stderr or p.stdout).strip()[:200])


def delete_socket_token():
    subprocess.run(["/usr/bin/security", "delete-generic-password", "-a", getpass.getuser(), "-s", SOCKET_ITEM],
                   capture_output=True, timeout=20)


def socket_alerts(job, eco, items, budget=None):
    """{(name, version): [(alert type, severity, action), ...]} from Socket.dev for [(name, version, max age)],
    cached in state.json. Versions Socket hasn't scanned are left out. None = no token or not covered.
    budget = {"left": n} caps the lookups (shared across calls); items not looked up yet come first."""
    t = SOCKET_TYPE.get(eco)
    token = t and socket_token()
    if not token:
        return None
    with _socket_lock:
        cache = store.data.setdefault("socket_cache", {})
        keys, todo, queued = {}, [], set()
        for n, v, age in items:
            k = socket_purl(t, n, v)
            keys[(n, v)] = k
            c = cache.get(k)
            if (not c or now() - c["t"] > age) and k not in queued:
                queued.add(k)
                todo.append(k)
        for i in range(0, len(todo), 1000):  # 1024 per request, 100 quota each whatever the size
            chunk = todo[i:i + 1000]
            if budget is not None:
                if budget["left"] <= 0:
                    job.log("# Socket: %d %s versions left for later scans" % (len(todo) - i, t))
                    break
                budget["left"] -= 1
            q = json.loads(socket_api(token, "quota"))
            store["socket_quota"] = dict(q, checked_at=now())
            if q.get("quota", 0) < 100:
                job.log("! Socket quota used up (refills %s) — using cached answers for %d versions"
                        % (q.get("nextWindowRefresh") or "soon", len(todo) - i))
                break
            if not store.data.get("socket_org"):
                orgs = json.loads(socket_api(token, "organizations")).get("organizations") or {}
                store["socket_org"] = next(iter(orgs.values()))["slug"]
            out = socket_api(token, "orgs/%s/purl?alerts=true&compact=true&purlErrors=true" % quote(store["socket_org"]),
                             {"components": [{"purl": k} for k in chunk]}, timeout=180)
            store["socket_quota"]["quota"] = q["quota"] - 100
            found = {}
            for d in iter_json(out):
                if "name" not in d or not SOCKET_RELEASE.search(d.get("release") or ""):
                    continue
                name = d["namespace"] + "/" + d["name"] if d.get("namespace") else d["name"]
                found.setdefault(socket_purl(d["type"], name, d["version"]), set()).update(
                    (a["type"], a.get("severity", ""), a.get("action", "")) for a in d.get("alerts") or []
                    if a.get("action") in ("error", "warn") or a["type"] in SOCKET_LABEL)
            for k in chunk:
                cache[k] = {"t": now(), "a": sorted(found[k]) if k in found else None}
        for k in [k for k, c in cache.items() if now() - c["t"] > 7 * 86400]:
            del cache[k]
        return {nv: cache[k]["a"] for nv, k in keys.items() if k in cache and cache[k]["a"] is not None}


def osv_fix(vuln, name, eco=None):
    """Fixed versions for the package (in this ecosystem: a distro advisory covers many releases)."""
    fixed = []
    for a in vuln.get("affected", []):
        if a.get("package", {}).get("name") != name or (eco and a["package"].get("ecosystem") != eco):
            continue
        for r in a.get("ranges", []):
            fixed += [e["fixed"] for e in r.get("events", []) if "fixed" in e and e["fixed"] not in fixed]
    return ", ".join(fixed[:2]) or "none"


def osv_severity(vuln):
    """GHSA's rating, else the distro's own (Debian urgency, Ubuntu priority), else from the CVSS v3 vector."""
    sev = (vuln.get("database_specific") or {}).get("severity")
    if sev:
        return sev
    for a in vuln.get("affected", []):
        urgency = (a.get("ecosystem_specific") or {}).get("urgency") or ""
        if urgency in ("unimportant", "low", "medium", "high"):
            return "low" if urgency == "unimportant" else urgency
    scores = {s.get("type"): s.get("score") or "" for s in vuln.get("severity") or []}
    if scores.get("Ubuntu"):
        return "low" if scores["Ubuntu"] == "negligible" else scores["Ubuntu"]
    score = cvss3_score(scores.get("CVSS_V3") or "")
    if score is None:
        return "unknown"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def cvss3_score(vector):
    """CVSS v3.x base score from its vector string (None if it isn't one)."""
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    w = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44}, "UI": {"N": .85, "R": .62}}
    cia = {"H": .56, "L": .22, "N": 0}
    try:
        changed = m["S"] == "C"
        pr = ({"N": .85, "L": .68, "H": .5} if changed else {"N": .85, "L": .62, "H": .27})[m["PR"]]
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        expl = 8.22 * w["AV"][m["AV"]] * w["AC"][m["AC"]] * pr * w["UI"][m["UI"]]
    except KeyError:
        return None
    impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    total = min((1.08 if changed else 1) * (impact + expl), 10)
    return -(-round(total * 100000) // 10000) / 10  # CVSS "round up" to one decimal


# ---------------------------------------------------------------- managers

class Manager:
    id = label = desc = icon = ""
    color = "green"
    actions = ("scan", "audit", "update")
    hold = None  # reason updates are held back
    osv_eco = None  # OSV ecosystem for the malware check (None = not covered)
    separate = False  # True = left out of the dashboard's headline totals
    unit = "pkgs"
    ignore_key = None  # separate managers: store key listing rows marked as deliberate targets / not mine

    def available(self):
        return True

    def ignored(self):
        """Rows marked as deliberate targets / not mine: their CVEs and malware hits aren't counted."""
        return set(store.data.get(self.ignore_key) or []) if self.ignore_key else set()

    def osv_name(self, p):
        return p["name"]

    def dep_tree(self, job):
        """Everything installed, dependencies included: [(osv name, version, top-level package)]."""
        return []

    def released(self, job, p):
        """Upload time of p's latest version from the registry (epoch), if it has one."""
        return None

    def gate(self, job):
        """{(kind, name): reason} for outdated packages this update mustn't install: known malware
        always, and anything still in its cooldown period unless this is a forced single update."""
        res = {}
        for key, p in inv_pkgs(self.id).items():
            if job.only and key != job.only:
                continue
            if p.get("blocked"):
                res[key] = "blocked: " + flag_text(p["blocked"])
            elif not job.force and cooldown_left(p) > 0:
                res[key] = "in cooldown period, %s remaining" % left_text(cooldown_left(p))
        for (kind, name), why in sorted(res.items()):
            job.log("hold %s: %s" % (name, why))
        return res

    def meta(self):
        return {"id": self.id, "label": self.label, "desc": self.desc, "color": self.color,
                "icon": self.icon, "actions": list(self.actions), "hold": self.hold,
                "available": self.available(), "separate": self.separate, "unit": self.unit}


class Uv(Manager):
    id, label, icon, color = "uv", "uv tools", "py", "green"
    desc = "Python CLIs installed with `uv tool install` (~/.local/share/uv/tools)"
    tools = HOME / ".local/share/uv/tools"
    osv_eco = "PyPI"

    def available(self):
        return bool(which("uv"))

    def freeze(self, job):
        """{tool: ["name==version", ...]} for every tool environment."""
        res = {}
        for d in sorted(self.tools.iterdir()):
            py = d / "bin/python"
            if py.exists():
                _, out = job.run(["uv", "pip", "freeze", "--python", py], quiet=True)
                res[d.name] = [l for l in out.splitlines() if "==" in l and not l.startswith("-e")]
        return res

    def dep_tree(self, job):
        return [(*l.split("==", 1), tool) for tool, reqs in self.freeze(job).items() for l in reqs]

    def released(self, job, p):
        return pypi_released(p["name"], p["latest"])

    def receipt(self, tool):
        """Requirements from uv-receipt.toml (no tomllib on 3.9): [{name, specifier|directory|git|...}]."""
        try:
            text = (self.tools / tool / "uv-receipt.toml").read_text()
        except OSError:
            return []
        block = re.search(r"^requirements = \[(.*?)\]$", text, re.S | re.M)
        return [dict(re.findall(r'([\w-]+) = "([^"]*)"', e)) for e in re.findall(r"\{([^{}]*)\}", block.group(1))] if block else []

    def source(self, tool):
        """(note, local_path) explaining why a tool may not move to `latest`."""
        notes, local = [], None
        for r in self.receipt(tool):
            src = r.get("directory") or r.get("path") or r.get("editable")
            if r.get("name") == tool:
                if src:
                    local = src
                    notes.append("local: " + src)
                elif r.get("git"):
                    notes.append("git: " + r["git"])
                elif r.get("specifier"):
                    notes.append("pinned: %s%s" % (tool, r["specifier"]))
            elif r.get("specifier"):
                notes.append("--with %s%s (limits upgrades)" % (r["name"], r["specifier"]))
        if local and local.startswith(str(HOME / "Documents")):
            notes.append("in ~/Documents: background service can't read it — upgrade from a terminal")
        return " · ".join(notes), local

    def scan(self, job):
        _, out = job.run(["uv", "tool", "list"])
        _, outd = job.run(["uv", "tool", "list", "--outdated"], timeout=300)
        latest = dict(re.findall(r"^(\S+) v\S+ \[latest: ([^\]]+)\]", outd, re.M))
        return [pkg(n, v, latest.get(n), "tool", self.source(n)[0])
                for n, v in re.findall(r"^([^\s-]\S*) v(\d\S*)", out, re.M)]

    def audit(self, job):
        res = []
        for tool, reqs in self.freeze(job).items():
            res += pip_audit(job, reqs, tool)
        return res

    def update(self, job, only=None):
        # one tool at a time so a single failure doesn't hide the others' results.
        # --exclude-newer keeps the tool AND its dependencies to releases past the cooldown period.
        gate = self.gate(job)
        cool = [] if job.force else ["--exclude-newer", iso(cooldown_cutoff())]
        _, out = job.run(["uv", "tool", "list"], quiet=True)
        done, skipped, bad = [], [], []
        for n in re.findall(r"^([^\s-]\S*) v\d", out, re.M):
            if only and n != only[1]:
                continue
            local = self.source(n)[1]
            why = gate.get(("tool", n), "")
            if local and local.startswith(str(HOME / "Documents")):
                job.log("skip %s: installed from %s, which launchd agents can't read" % (n, local))
                skipped.append(n)
            elif why.startswith("blocked:"):
                skipped.append(n)
            elif job.stream(["uv", "tool", "upgrade", n] + cool, timeout=1800) == 0:
                done.append(n)
            else:
                bad.append(n)
        if only and not (done or skipped or bad):
            raise RuntimeError("%s isn't installed as a uv tool" % only[1])
        if only and skipped and gate.get(only):
            raise RuntimeError("%s not updated: %s" % (only[1], gate[only]))
        summary = "upgraded %d tools" % len(done) + (", skipped " + ", ".join(skipped) if skipped else "")
        if bad:
            raise RuntimeError(summary + "; failed: " + ", ".join(bad))
        return summary


class Npm(Manager):
    id, label, icon, color = "npm", "npm globals", "js", "blue"
    desc = "Global npm packages in fnm's default Node"
    osv_eco = "npm"

    def available(self):
        return bool(which("npm"))

    def dep_tree(self, job):
        _, out = job.run(["npm", "ls", "-g", "--all", "--json"], quiet=True, timeout=300)
        res = set()

        def walk(deps, top):
            for name, info in (deps or {}).items():
                if info.get("version"):
                    res.add((name, info["version"], top or name))
                walk(info.get("dependencies"), top or name)
        walk(loads(out, {}).get("dependencies"), None)
        return sorted(res)

    def released(self, job, p):
        data = http_json("https://registry.npmjs.org/" + p["name"].replace("/", "%2f"), timeout=60)
        return parse_iso((data.get("time") or {}).get(p["latest"]))

    def root(self, job):
        _, out = job.run(["npm", "root", "-g"])
        return Path(out.strip())

    def installed(self, job):
        _, out = job.run(["npm", "ls", "-g", "--depth=0", "--json"])
        return loads(out, {}).get("dependencies", {})

    def scan(self, job):
        root = self.root(job)
        _, out = job.run(["npm", "outdated", "-g", "--json"], timeout=300)
        outd = loads(out, {})
        res = []
        for name, info in sorted(self.installed(job).items()):
            p = root / name
            note = "npm link → %s" % os.path.realpath(p) if p.is_symlink() else ""
            p = pkg(name, info.get("version"), (outd.get(name) or {}).get("latest"),
                    "linked" if note else "global", note)
            cur, lat = str(p["version"]).split(".")[0], str(p["latest"] or "").split(".")[0]
            if name == "npm" and p["latest"] and lat != cur and not store["settings"]["npm_major_self_update"]:
                # the update button keeps npm on its major, so don't nag about one it won't install
                p["outdated"] = False
                p["note"] = ("npm %s available — major upgrades held (enable in ~/.pkgdashrc, "
                             "or run `npm i -g npm@latest`)" % p["latest"])
            res.append(p)
        return res

    @staticmethod
    def parse_audit(data, context):
        res = []
        for name, v in (data.get("vulnerabilities") or {}).items():
            fx = v.get("fixAvailable")
            if fx is True:
                fix = "yes"
            elif not fx:
                fix = "none"
            else:
                fix = "%s@%s%s" % (fx["name"], fx["version"], " (major)" if fx.get("isSemVerMajor") else "")
            for via in v.get("via", []):
                if isinstance(via, dict):
                    vid = str(via.get("url", "")).rstrip("/").rsplit("/", 1)[-1] or str(via.get("source"))
                    res.append(finding(name, via.get("range", ""), vid, via.get("severity") or v.get("severity"),
                                       via.get("title", ""), fix, context))
        return res

    def audit(self, job):
        root, res, wrap = self.root(job), [], {}
        tmp = Path(tempfile.mkdtemp(prefix="pkgdash-npm-"))
        try:
            for name, info in sorted(self.installed(job).items()):
                src = root / name
                try:
                    os.listdir(src)
                except OSError as e:
                    # e.g. an `npm link` into ~/Documents, which macOS (TCC) hides from launchd agents
                    job.log("! skip %s: can't read %s (%s) — audit it from a terminal instead"
                            % (name, os.path.realpath(src), e.strerror))
                    continue
                has_lock = (src / "package-lock.json").exists() or (src / "npm-shrinkwrap.json").exists()
                if not has_lock and not (src / "node_modules").is_dir():
                    wrap[name] = info.get("version")
                    continue
                dst = tmp / name.replace("/", "_")
                job.run(["cp", "-RL", src, dst], quiet=True)
                if not has_lock:
                    job.run(["npm", "i", "--package-lock-only", "--ignore-scripts", "--no-audit",
                             "--omit=dev"], cwd=dst, quiet=True, timeout=600)
                _, out = job.run(["npm", "audit", "--json", "--omit=dev"], cwd=dst, quiet=True, timeout=300)
                data = loads(out, {})
                if "error" in data or "vulnerabilities" not in data:
                    wrap[name] = info.get("version")
                    continue
                found = self.parse_audit(data, name)
                job.log("  %s: %d findings" % (name, len(found)))
                res += found
            if wrap:  # bundled/lockless packages: audit the package itself via a wrapper project
                w = tmp / "_wrapper"
                w.mkdir()
                (w / "package.json").write_text(json.dumps({"name": "pkgdash-wrap", "version": "1.0.0",
                                                            "dependencies": wrap}))
                # --legacy-peer-deps: peers (a plugin and the tool it extends) are separate
                # globals audited on their own; resolving them here would audit phantom fresh copies
                job.run(["npm", "i", "--package-lock-only", "--ignore-scripts", "--no-audit",
                         "--legacy-peer-deps"], cwd=w,
                        quiet=True, timeout=600)
                _, out = job.run(["npm", "audit", "--json"], cwd=w, quiet=True, timeout=300)
                found = self.parse_audit(loads(out, {}), " + ".join(sorted(wrap)))
                job.log("  wrapper %s: %d findings" % (", ".join(wrap), len(found)))
                res += found
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return res

    def update(self, job, only=None):
        gate = self.gate(job)
        root, specs = self.root(job), []
        for name, info in self.installed(job).items():
            if only and name != only[1]:
                continue
            if gate.get(("global", name), "").startswith("blocked:"):
                continue
            if (root / name).is_symlink():
                job.log("skip %s (npm link — update its repo instead)" % name)
            elif name == "npm" and not store["settings"]["npm_major_self_update"]:
                specs.append("npm@%s" % str(info.get("version", "11")).split(".")[0])
            else:
                specs.append(name + "@latest")
        if only and not specs:
            raise RuntimeError("%s not updated: %s" % (only[1], gate.get(("global", only[1])) or "npm-linked or not installed globally"))
        # reinstalling every global (not only outdated ones) also refreshes their nested deps;
        # --before keeps them and their dependencies to releases past the cooldown period
        cool = [] if job.force else ["--before=" + iso(cooldown_cutoff())]
        if job.stream(["npm", "i", "-g", "--no-fund", "--no-audit"] + cool + sorted(specs), timeout=1800) != 0:
            raise RuntimeError("npm install -g failed")
        return "reinstalled " + (specs[0] if only else "%d globals" % len(specs))


class Brew(Manager):
    id, label, icon, color = "brew", "homebrew", "beer", "amber"
    desc = "Homebrew formulae and casks (vulns via brew-vulns / OSV)"
    bottle_repo = {}  # formula name → its ghcr.io repo, for release dates (filled by each scan)

    def available(self):
        return bool(which("brew"))

    def outdated(self, job):
        _, out = job.run(["brew", "outdated", "--json=v2"], timeout=600)
        return loads(out, {"formulae": [], "casks": []})

    def scan(self, job):
        job.run(["brew", "update", "--quiet"], timeout=600)
        _, f = job.run(["brew", "list", "--formula", "--versions"], quiet=True)
        _, c = job.run(["brew", "list", "--cask", "--versions"], quiet=True)
        _, leaves = job.run(["brew", "leaves", "--installed-on-request"], quiet=True)
        leaves = {l.strip().rsplit("/", 1)[-1] for l in leaves.splitlines()}
        o = self.outdated(job)
        lf = {x["name"]: x["current_version"] for x in o.get("formulae", [])}
        lc = {x["name"]: x["current_version"] for x in o.get("casks", [])}
        self.bottle_repos(job, sorted(lf))
        res = []
        for line in f.splitlines():
            parts = line.split()
            if parts:
                n = parts[0]
                res.append(pkg(n, parts[-1], lf.get(n), "formula", "" if n in leaves else "dependency"))
        for line in c.splitlines():
            parts = line.split()
            if parts:
                res.append(pkg(parts[0], parts[-1], lc.get(parts[0]), "cask"))
        return res

    def bottle_repos(self, job, names):
        """Where each outdated homebrew/core formula's bottles live on ghcr.io ("homebrew/core/python/3.13")."""
        self.bottle_repo = {}
        if not names:
            return
        _, out = job.run(["brew", "info", "--json=v2", "--formula"] + names, quiet=True, timeout=300)
        for x in loads(out, {}).get("formulae", []):
            files = ((x.get("bottle") or {}).get("stable") or {}).get("files") or {}
            url = next(iter(files.values()), {}).get("url", "")
            m = re.match(r"https://ghcr\.io/v2/(homebrew/core/[\w.+@/-]+)/blobs/", url)
            if m:
                self.bottle_repo[x["name"]] = m.group(1)

    def released(self, job, p):
        """Homebrew has no release dates, but a core bottle's manifest says when it was built. The plain version
        tag is the first build (rebuilds are tagged -1, -2, ...), which comes soon after upstream's release.
        Casks and tap formulae have none, so their cooldown counts from when a scan first saw them."""
        repo = self.bottle_repo.get(p["name"]) if p["kind"] == "formula" else None
        if not repo:
            return None
        # "QQ==" is ghcr.io's anonymous token, enough for public images like Homebrew's bottles
        data = http_json("https://ghcr.io/v2/%s/manifests/%s" % (repo, quote(p["latest"])),
                         headers={"Authorization": "Bearer QQ==", "Accept": "application/vnd.oci.image.index.v1+json"})
        return parse_iso((data.get("annotations") or {}).get("org.opencontainers.image.created"))

    def audit(self, job):
        _, out = job.run(["brew", "vulns", "--json", "-m", "0"], quiet=True, timeout=1800)
        data = loads(out, None)
        if data is None:
            raise RuntimeError("brew vulns gave no JSON (is the homebrew/brew-vulns tap installed?)")
        res = []
        for f in data.get("findings", []):
            for v in f.get("vulnerabilities", []):
                fix = ", ".join(v.get("fixed_versions") or []) or "unreleased upstream"
                res.append(finding(f["formula"], f.get("version"), v["id"], v.get("severity"),
                                   v.get("summary"), fix, f["formula"], v.get("aliases", [])))
        return res

    def running_app(self, job, cask):
        _, out = job.run(["brew", "info", "--cask", "--json=v2", cask], quiet=True)
        apps = []
        for c in loads(out, {}).get("casks", []):
            for art in c.get("artifacts", []):
                for a in art.get("app", []) if isinstance(art, dict) else []:
                    if isinstance(a, str):
                        apps.append(a)
        for a in apps:
            if subprocess.run(["/usr/bin/pgrep", "-f", "/Applications/%s/" % a], capture_output=True).returncode == 0:
                return a
        return None

    def update(self, job, only=None):
        gate = self.gate(job)
        if only:
            if gate.get(only):
                raise RuntimeError("%s not updated: %s" % (only[1], gate[only]))
            return self.update_one(job, *only)
        job.stream(["brew", "update"], timeout=900)
        # the cooldown only knows about versions a scan has dated (bottle build time, or when the scan
        # first saw it), so only upgrade what the scan saw: a version that appeared since then waits.
        inv, o = inv_pkgs(self.id), self.outdated(job)

        def ready(kind, items):
            res = []
            for x in items:
                p = inv.get((kind, x["name"]))
                if not p or p.get("latest") != x.get("current_version"):
                    job.log("hold %s: %s is newer than the last scan — waits for its cooldown" % (x["name"], x.get("current_version")))
                elif (kind, x["name"]) not in gate:
                    res.append(x["name"])
            return res
        formulae, casks = ready("formula", o.get("formulae", [])), ready("cask", o.get("casks", []))
        held = len(o.get("formulae", [])) + len(o.get("casks", [])) - len(formulae) - len(casks)
        rc = job.stream(["brew", "upgrade", "--formula"] + formulae, timeout=3600) if formulae else 0
        skipped = []
        if store["settings"]["brew_skip_running_casks"]:
            for c in list(casks):
                app = self.running_app(job, c)
                if app:
                    job.log("skip cask %s — %s is running" % (c, app))
                    casks.remove(c)
                    skipped.append(c)
        if casks:
            rc |= job.stream(["brew", "upgrade", "--cask"] + casks, timeout=3600)
        if store["settings"]["brew_cleanup"]:
            job.stream(["brew", "cleanup"], timeout=900)
        if rc != 0:
            raise RuntimeError("brew upgrade reported errors (see log)")
        return "upgraded %d formulae + %d casks%s%s" % (
            len(formulae), len(casks), (", skipped running: " + ", ".join(skipped)) if skipped else "",
            ", %d held (cooldown/malware)" % held if held else "")

    def update_one(self, job, kind, name):
        # no `brew update` first: the scan that showed it as outdated already refreshed the index
        flag = "--cask" if kind == "cask" else "--formula"
        if kind == "cask":
            app = self.running_app(job, name)
            if app:
                raise RuntimeError("%s is running — quit it and try again" % app)
        if job.stream(["brew", "upgrade", flag, name], timeout=3600) != 0:
            raise RuntimeError("brew upgrade %s failed (see log)" % name)
        return "upgraded " + name


class Pip(Manager):
    id, label, icon, color = "pip", "pip (system pythons)", "py", "green"
    desc = "pip packages in Homebrew's Pythons, plus `pip install --user` strays in macOS's /usr/bin/python3"
    actions = ("scan", "audit")
    hold = ("Updates disabled by design: these Pythons belong to Homebrew / macOS. Install tools with "
            "`uv tool install` instead — anything marked 'stray' here should move to uv.")

    def pythons(self):
        """(interpreter, kind label, extra pip args)."""
        res = [(p, p.name, []) for p in sorted(Path("/opt/homebrew/bin").glob("python3.*"))
               if re.fullmatch(r"python3\.\d+", p.name)]
        if Path("/usr/bin/python3").exists():  # macOS python: only user-installed packages are ours
            res.append((Path("/usr/bin/python3"), "macos python3 --user", ["--user"]))
        return res

    def available(self):
        return bool(self.pythons())

    def released(self, job, p):
        return pypi_released(p["name"], p["latest"])

    def scan(self, job):
        res = []
        for py, kind, extra in self.pythons():
            _, out = job.run([py, "-m", "pip", "list", "--format=json"] + extra, quiet=True)
            _, outd = job.run([py, "-m", "pip", "list", "--outdated", "--format=json"] + extra, quiet=True, timeout=300)
            latest = {d["name"]: d.get("latest_version") for d in loads(outd, [])}
            _, insp = job.run([py, "-m", "pip", "inspect"] + extra, quiet=True)
            installer = {i["metadata"]["name"].lower(): i.get("installer", "")
                         for i in loads(insp, {}).get("installed", [])}
            for d in loads(out, []):
                who = installer.get(d["name"].lower(), "")
                if who == "brew":
                    note = "installed by Homebrew"
                elif extra or (who == "pip" and d["name"] not in ("pip", "setuptools", "wheel")):
                    note = "stray pip install — move to uv"
                else:
                    note = ""
                res.append(pkg(d["name"], d["version"], latest.get(d["name"]), kind, note))
        return res

    def audit(self, job):
        res = []
        for py, kind, extra in self.pythons():
            _, out = job.run([py, "-m", "pip", "list", "--format=freeze"] + extra, quiet=True)
            reqs = [l for l in out.splitlines() if "==" in l
                    and not re.match(r"(pip|setuptools|wheel)==", l)]
            res += pip_audit(job, reqs, kind)
        return res


class Go(Manager):
    id, label, icon, color = "go", "go binaries", "go", "blue"
    desc = "Binaries built with `go install` in ~/go/bin (rebuilt with the current Go on update)"
    bindir = HOME / "go/bin"
    osv_eco = "Go"

    def available(self):
        return bool(which("go")) and self.bindir.is_dir()

    def osv_name(self, p):
        return p.get("module") or p["name"]

    def bins(self, job):
        res = []
        for b in sorted(self.bindir.iterdir()):
            _, out = job.run(["go", "version", "-m", b], quiet=True)
            gov = re.search(r":\s*(go[\d.]+)", out)
            path = re.search(r"^\s*path\s+(\S+)", out, re.M)
            mod = re.search(r"^\s*mod\s+(\S+)\s+(\S+)", out, re.M)
            if path and mod:
                res.append({"bin": b, "path": path.group(1), "mod": mod.group(1),
                            "ver": mod.group(2), "go": gov.group(1) if gov else "?",
                            "deps": re.findall(r"^\s*dep\s+(\S+)\s+(v\S+)", out, re.M)})
        return res

    def dep_tree(self, job):
        return [(m, v, b["bin"].name) for b in self.bins(job)
                for m, v in [(b["mod"], b["ver"])] + b["deps"] if v.startswith("v")]

    def scan(self, job):
        _, cur = job.run(["go", "env", "GOVERSION"])
        cur = cur.strip()
        res = []
        tmp = tempfile.mkdtemp(prefix="pkgdash-go-")
        try:
            for b in self.bins(job):
                _, out = job.run(["go", "list", "-m", "-json", b["mod"] + "@latest"], cwd=tmp, quiet=True, timeout=120)
                info = loads(out, {})
                latest = info.get("Version")
                stale_go = b["go"] != cur
                p = pkg(b["bin"].name, b["ver"], latest if latest and latest != b["ver"] else None, "go-install",
                        "%s · built with %s%s" % (b["path"], b["go"], " (current %s → rebuild)" % cur if stale_go else ""))
                p["outdated"] = p["outdated"] or stale_go
                p["module"] = b["mod"]
                if p["latest"]:
                    p["released"] = parse_iso(info.get("Time"))
                res.append(p)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return res

    def audit(self, job):
        res = []
        for b in self.bins(job):
            _, out = job.run(["go", "run", "golang.org/x/vuln/cmd/govulncheck@" + GOVULNCHECK_VERSION, "-mode=binary",
                              "-format", "json", b["bin"]], quiet=True, timeout=900)
            osv, found = {}, []
            for msg in iter_json(out):
                if "osv" in msg:
                    osv[msg["osv"]["id"]] = msg["osv"]
                elif "finding" in msg:
                    found.append(msg["finding"])
            seen = set()
            for f in found:
                # symbol-level only (vulnerable code actually called), matching govulncheck's text output
                if f["osv"] in seen or not any(t.get("function") for t in f.get("trace") or []):
                    continue
                seen.add(f["osv"])
                t = (f.get("trace") or [{}])[0]
                o = osv.get(f["osv"], {})
                res.append(finding(t.get("module", b["mod"]), t.get("version", ""), f["osv"], "unknown",
                                   o.get("summary") or o.get("details", ""), f.get("fixed_version") or "none",
                                   b["bin"].name, o.get("aliases", [])))
            job.log("  %s: %d findings" % (b["bin"].name, len(seen)))
        return res

    def update(self, job, only=None):
        bins = [b for b in self.bins(job) if not only or b["bin"].name == only[1]]
        if only and not bins:
            raise RuntimeError("%s isn't in ~/go/bin" % only[1])
        gate, bad = self.gate(job), []
        for b in bins:
            why = gate.get(("go-install", b["bin"].name))
            if only and why:
                raise RuntimeError("%s not updated: %s" % (only[1], why))
            # held back: still rebuild the version we have, so it picks up the current Go
            target = b["ver"] if why and b["ver"].startswith("v") else "latest"
            if why and target == "latest":
                continue
            if job.stream(["go", "install", "%s@%s" % (b["path"], target)], timeout=1800) != 0:
                bad.append(b["bin"].name)
        if bad:
            raise RuntimeError("go install failed for: " + ", ".join(bad))
        return "rebuilt " + (only[1] if only else "all") + " with current Go"


class Cargo(Manager):
    id, label, icon, color = "cargo", "cargo crates", "rs", "amber"
    desc = "Binaries from `cargo install` (OSV check covers the top-level crate only)"
    osv_eco = "crates.io"

    def available(self):
        return bool(which("cargo"))

    def dep_tree(self, job):
        return [(n, v, n) for n, v, src in self.crates(job) if not src]

    def crates(self, job):
        _, out = job.run(["cargo", "install", "--list"])
        return [(n, v, src or "") for n, v, src in re.findall(r"^(\S+) v(\S+)(?: \((.+)\))?:", out, re.M)]

    def scan(self, job):
        res = []
        for n, v, src in self.crates(job):
            latest, released = None, None
            if not src:
                try:
                    data = http_json("https://crates.io/api/v1/crates/%s" % n)
                    latest = data["crate"]["max_stable_version"]
                    released = next((parse_iso(x.get("created_at")) for x in data.get("versions", [])
                                     if x.get("num") == latest), None)
                except Exception as e:
                    job.log("! crates.io lookup failed for %s: %s" % (n, e))
            p = pkg(n, v, latest, "crate", src)
            if p["latest"] and released:
                p["released"] = released
            res.append(p)
        return res

    def audit(self, job):
        cr = self.crates(job)
        if not cr:
            return []
        q = {"queries": [{"package": {"name": n, "ecosystem": "crates.io"}, "version": v} for n, v, _ in cr]}
        data = http_json("https://api.osv.dev/v1/querybatch", q)
        res = []
        for (n, v, _), r in zip(cr, data.get("results", [])):
            for hit in r.get("vulns", []):
                full = http_json("https://api.osv.dev/v1/vulns/%s" % hit["id"])
                res.append(finding(n, v, hit["id"], osv_severity(full), full.get("summary") or full.get("details", ""),
                                   osv_fix(full, n), n, full.get("aliases", [])))
        return res

    def update(self, job, only=None):
        crates = [c for c in self.crates(job) if not only or c[0] == only[1]]
        if only and not crates:
            raise RuntimeError("%s isn't installed with cargo" % only[1])
        if only and crates[0][2]:
            raise RuntimeError("%s was installed from %s — update it there" % (only[1], crates[0][2]))
        gate, bad = self.gate(job), []
        if only and gate.get(only):
            raise RuntimeError("%s not updated: %s" % (only[1], gate[only]))
        for n, v, src in crates:
            if src:
                job.log("skip %s (installed from %s)" % (n, src))
                continue
            if ("crate", n) in gate:
                continue
            p = inv_pkgs(self.id).get(("crate", n)) or {}
            if not job.force and not p.get("outdated"):
                continue  # nothing newer (or not scanned yet): don't pull whatever just got published
            ver = ["--version", p["latest"]] if p.get("latest") else []
            if job.stream(["cargo", "install", n, "--locked"] + ver, timeout=3600) != 0:
                bad.append(n)
        if bad:
            raise RuntimeError("cargo install failed for: " + ", ".join(bad))
        return "cargo install --locked " + (only[1] if only else "for each crate")


# each installed gem as [name, newest version, [every version installed], origin]; origin is "default" (part of
# Ruby itself), "bundled" (ships with Ruby, in its own gem dir) or "gem" (installed with `gem install`)
RUBY_GEMS = """
require "json"
own = File.join(RbConfig::CONFIG["rubylibprefix"], "gems", RbConfig::CONFIG["ruby_version"])
puts JSON.generate(Gem::Specification.group_by(&:name).sort.map { |n, ss|
  [n, ss.max_by(&:version).version.to_s, ss.map { |s| s.version.to_s }.uniq,
   ss.any?(&:default_gem?) ? "default" : ss.any? { |s| s.base_dir == own } ? "bundled" : "gem"] })
"""
GEM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
GEM_VERSION = re.compile(r"^[0-9][0-9A-Za-z.]*$")


class Gem(Manager):
    id, label, icon, color = "gem", "ruby gems", "rb", "amber"
    desc = "Gems in Homebrew's Ruby (`gem install`), including the ones that ship with Ruby"
    osv_eco = "RubyGems"

    def ruby(self):
        r = which("ruby")
        return r if r and not r.startswith("/usr/bin/") else None  # macOS's own Ruby belongs to Apple

    def gem(self):
        return os.path.join(os.path.dirname(os.path.realpath(self.ruby())), "gem")  # the one that goes with it

    def available(self):
        return bool(self.ruby())

    def gems(self, job):
        rc, out = job.run([self.ruby(), "-e", RUBY_GEMS], quiet=True, timeout=120)
        data = loads(out, None)
        if rc != 0 or not isinstance(data, list):
            raise RuntimeError("couldn't list the installed gems: " + out.strip()[-200:])
        return [x for x in data if isinstance(x, list) and len(x) == 4]

    def dep_tree(self, job):
        return [(n, v, n) for n, _, vers, _ in self.gems(job) for v in vers]

    def scan(self, job):
        rc, out = job.run([self.gem(), "outdated"], quiet=True, timeout=300)
        if rc != 0:
            job.log("! gem outdated failed (exit %s); versions only" % rc)
        latest = dict(re.findall(r"^(\S+) \(\S+ < (\S+)\)$", out, re.M))
        res = []
        for n, v, vers, origin in self.gems(job):
            notes = [{"default": "default gem (part of Ruby)", "bundled": "bundled with Ruby"}.get(origin, "")]
            older = [x for x in vers if x != v]
            if older:
                notes.append("also installed: " + ", ".join(older[:5]))
            p = pkg(n, v, latest.get(n), "gem", " · ".join(x for x in notes if x))
            p["origin"] = origin
            res.append(p)
        self.uncount_rubys_own(job, res)
        return res

    def uncount_rubys_own(self, job, rows):
        """Gems that ship with Ruby also get newer with `brew upgrade ruby`, so a newer release of one only counts
        as outdated when OSV knows a vulnerability in the installed version. The rest are marked `newer`: still
        shown, and updatable from their row, but not in the outdated counts or an update-all."""
        own = [p for p in rows if p["outdated"] and p["origin"] != "gem"]
        if not own:
            return
        try:
            data = http_json("https://api.osv.dev/v1/querybatch", {"queries": [
                {"package": {"name": p["name"], "ecosystem": "RubyGems"}, "version": p["version"]} for p in own]}, timeout=90)
        except Exception as e:
            job.log("! OSV check of Ruby's own gems failed, counting them all as outdated: %s" % e)
            return
        for p, r in zip(own, data.get("results", [])):
            if not any(not x["id"].startswith("MAL-") for x in r.get("vulns") or []):
                p["outdated"], p["newer"] = False, True

    def released(self, job, p):
        data = http_json("https://rubygems.org/api/v1/versions/%s.json" % quote(p["name"]))
        times = [parse_iso(x.get("created_at")) for x in (data if isinstance(data, list) else [])
                 if isinstance(x, dict) and x.get("number") == p["latest"]]
        return min((t for t in times if t), default=None)  # platform builds of one version come out together

    def audit(self, job):
        res = osv_audit(job, [("gems", "RubyGems", [(n, v) for n, v, _ in self.dep_tree(job)], "installed gems")])
        for f in res:
            f["context"] = f["pkg"]
        return res

    def update(self, job, only=None):
        rows = [p for key, p in sorted(inv_pkgs(self.id).items()) if not only or key == only]
        if only and not rows:
            raise RuntimeError("%s isn't installed with gem" % only[1])
        gate, bad = self.gate(job), []
        if only and gate.get(only):
            raise RuntimeError("%s not updated: %s" % (only[1], gate[only]))
        for p in rows:
            # `newer` rows (Ruby's own gems, nothing known wrong) only when asked for by name
            wanted = p.get("outdated") or (only and p.get("newer"))
            if ("gem", p["name"]) in gate or not wanted or not p.get("latest"):
                continue
            if not (GEM_NAME.match(p["name"]) and GEM_VERSION.match(p["latest"])):
                job.log("skip %r: not a gem name and version" % p["name"])
                continue
            # the exact version the scan saw (and the cooldown dated); --conservative leaves dependencies
            # that already fit alone instead of pulling their newest releases too
            if job.stream([self.gem(), "install", p["name"], "--version", p["latest"], "--conservative",
                           "--no-document"], timeout=1800) != 0:
                bad.append(p["name"])
        if bad:
            raise RuntimeError("gem install failed for: " + ", ".join(bad))
        return "gem install " + (only[1] if only else "for each outdated gem")


# lockfile name → (kind shown on the projects page, OSV ecosystem)
LOCKFILES = {"package-lock.json": ("npm", "npm"), "yarn.lock": ("yarn", "npm"), "uv.lock": ("uv", "PyPI"),
             "poetry.lock": ("poetry", "PyPI"), "Cargo.lock": ("cargo", "crates.io"), "requirements.txt": ("pip", "PyPI"),
             "Gemfile.lock": ("bundler", "RubyGems")}


def lock_deps(fname, text):
    """[(name, version)] pinned by a lockfile, dependencies included (registry packages only)."""
    res = set()
    if fname == "package-lock.json":
        # lockfiles come from any project, so check every type rather than trust the shape
        data = loads(text, {})
        data = data if isinstance(data, dict) else {}
        packages = data.get("packages")
        for key, info in (packages.items() if isinstance(packages, dict) else ()):  # lockfile v2/v3
            if (isinstance(info, dict) and "node_modules/" in key and not info.get("link")
                    and isinstance(info.get("version"), str) and info["version"]):
                name = info.get("name")
                name = name if isinstance(name, str) and name else key.rsplit("node_modules/", 1)[1]
                if name:  # a bare "node_modules/" key names nothing (found by fuzzing)
                    res.add((name, info["version"]))
        if not packages:  # lockfile v1: nested "dependencies", walked without recursion
            todo = [data.get("dependencies")]
            while todo:
                deps = todo.pop()
                for n, info in (deps.items() if isinstance(deps, dict) else ()):
                    if isinstance(info, dict):
                        if n and isinstance(info.get("version"), str) and info["version"]:
                            res.add((n, info["version"]))
                        todo.append(info.get("dependencies"))
    elif fname == "yarn.lock":  # yarn 1 (`version "1.2.3"`) and yarn 2+ (`version: 1.2.3`)
        name = None
        for line in text.splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
                spec = line.rstrip().rstrip(":").split(",")[0].strip().strip('"')
                name = spec[:spec.index("@", 1)] if "@" in spec[1:] else None
            else:
                m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
                if m and name:
                    res.add((name, m.group(1)))
                    name = None
    elif fname == "requirements.txt":  # only exact pins say what's installed
        for line in text.splitlines():
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)", line)
            if m:
                res.add(m.groups())
    elif fname == "Gemfile.lock":  # GEM sections only: GIT and PATH sources aren't on rubygems.org
        section = None
        for line in text.splitlines():
            if line and not line[0].isspace():
                section = line.strip()
            elif section == "GEM":
                # "    nokogiri (1.16.0-arm64-darwin)": specs are indented 4, their dependencies 6
                m = re.match(r"    ([A-Za-z0-9][A-Za-z0-9._-]*) \(([0-9][^)\s]*)\)\s*$", line)
                if m:
                    res.add((m.group(1), m.group(2).split("-", 1)[0]))  # drop the platform
    else:  # TOML [[package]] tables: uv.lock, poetry.lock, Cargo.lock
        for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
            n = re.search(r'(?m)^name = "([^"]+)"', block)
            v = re.search(r'(?m)^version = "([^"]+)"', block)
            src = re.search(r"(?m)^source = (.+)$", block)
            if not (n and v):
                continue
            if fname == "Cargo.lock" and not (src and "registry+" in src.group(1)):
                continue  # path/git crates and the project itself
            if fname == "uv.lock" and not (src and "registry" in src.group(1)):
                continue  # the project itself, editable/path/git sources
            if fname == "poetry.lock" and re.search(r'(?m)^type = "(git|directory|file|url)"', block):
                continue
            res.add((n.group(1), v.group(1)))
    return sorted((n, v) for n, v in res if v and not re.search(r"[:/]", v))


def clean_projects_root(value):
    """A projects folder as "~/…", or None unless it's inside the home folder (and not ~/Library).
    Not resolved on disk: this service can't look inside folders like ~/Documents (TCC); the menu bar
    app reports it if it can't read the folder."""
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        return None
    p = os.path.normpath(os.path.expanduser(value.strip()))
    rel = os.path.relpath(p, HOME) if os.path.isabs(p) else ".."
    if rel == "." or rel.startswith("..") or rel.split("/")[0] == "Library":
        return None
    return "~/" + rel


def projects_root():
    return Path(os.path.expanduser(clean_projects_root(store["settings"].get("projects_root")) or "~/Documents"))


def enabled(m):
    return m.id not in (store["settings"].get("disabled_managers") or [])


def projects_sync(body):
    """The menu bar app's side of a projects scan: a manifest of the lockfiles in the projects folder,
    then each one we don't have yet, then done (or an error if it can't read the folder)."""
    def valid(path):
        path = os.path.normpath(str(path or ""))
        ok = path.startswith(str(projects_root()) + "/") and os.path.basename(path) in LOCKFILES
        return path if ok else None

    with store.lock:
        sync = store.data.setdefault("project_sync", {})
        files = store.data.setdefault("project_files", {})
        if body.get("error"):
            sync.update(error=str(body["error"])[:300], at=now())
            store.save()
            return {"ok": True}
        if "manifest" in body:
            man = {}
            for f in body["manifest"] or []:
                path = valid(f.get("path"))
                if path:
                    man[path] = float(f.get("mtime") or 0)
            removed = [p for p in files if p not in man]
            for p in removed:
                try:
                    (PROJECTS_DIR / files.pop(p)["file"]).unlink()
                except OSError:
                    pass
            need = sorted(p for p, mt in man.items() if p not in files or files[p]["mtime"] != mt)
            sync["changed"] = bool(sync.get("changed") or removed or need)
            sync["mtimes"] = man
            return {"need": need}
        if "upload" in body:
            u = body["upload"] or {}
            path = valid(u.get("path"))
            if not path or path not in sync.get("mtimes", {}):
                return {"error": "not in the manifest"}
            name = hashlib.sha1(path.encode(), usedforsecurity=False).hexdigest()[:16] + ".lock"
            PROJECTS_DIR.mkdir(exist_ok=True)
            (PROJECTS_DIR / name).write_text(str(u.get("content") or ""))
            files[path] = {"mtime": sync["mtimes"][path], "file": name}
            return {"ok": True}
        if body.get("done"):
            changed = sync.pop("changed", False)
            sync.pop("mtimes", None)
            sync.update(at=now(), files=len(files), error=None)
            store.save()
    if body.get("done"):
        if changed:
            runner.enqueue("projects", "scan", trigger="sync")
        return {"ok": True}
    return {"error": "bad request"}


_osv_vulns = {}  # vuln id → (fetched at, record), for project audits


def osv_vuln(vid):
    hit = _osv_vulns.get(vid)
    if not hit or now() - hit[0] > 86400:
        hit = _osv_vulns[vid] = (now(), http_json("https://api.osv.dev/v1/vulns/%s" % vid))
    return hit[1]


project_tasks = {}  # job id → lockfile fix for the menu bar app to run (it can read the projects folder, we can't)


class Projects(Manager):
    id, label, icon, color = "projects", "projects", "folder", "blue"
    desc = ("Lockfiles of the projects in your projects folder, sent over by the menu bar app: malware and CVE checks "
            "of every dependency. Fixes only rewrite a lockfile (nothing is installed); review and commit them in the repo")
    actions = ("scan", "audit", "update")  # update = fix one project's lockfile, from its row
    separate = True  # left out of the headline package/vuln totals (malware still counts)
    unit = "lockfiles"
    fixable = ("npm", "uv", "cargo")  # what the menu bar app knows how to fix without installing anything
    ignore_key = "project_ignore"

    def update(self, job, only=None):
        if not only:
            raise RuntimeError("projects are fixed one at a time, from their row")
        kind, rel = only
        if kind == "bundler":
            raise RuntimeError("pkgdash doesn't fix Gemfile.lock: Bundler would run the project's Gemfile, which is Ruby "
                               "code. Run `bundle update <gem>` in %s yourself" % rel)
        if kind not in self.fixable:
            raise RuntimeError("pkgdash can't fix %s lockfiles yet; update %s by hand" % (kind, rel))
        proj = self.projects().get(only)
        if not proj:
            raise RuntimeError("%s's lockfile is gone; rescan" % rel)
        eco, deps, path, _ = proj
        names = {n for n, _ in deps}
        pkgs = sorted({f["pkg"] for f in (store["vulns"].get(self.id) or {}).get("findings", [])
                       if f["context"] == rel and f["pkg"] in names})
        if kind != "npm" and not pkgs:
            raise RuntimeError("no vulnerable packages known in %s; run an audit first" % rel)
        task = project_tasks[job.id] = {"id": job.id, "kind": kind, "path": path, "pkgs": pkgs}
        job.log("# asking the menu bar app to fix %s: lockfile only, nothing gets installed or run" % path.replace(str(HOME), "~", 1))
        if pkgs:
            job.log("# upgrading: " + ", ".join(pkgs))
        try:
            for _ in range(900):
                if "rc" in task:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("the menu bar app didn't pick the fix up (is it running?)")
        finally:
            project_tasks.pop(job.id, None)
        job.log(task.get("output") or "")
        runner.enqueue(self.id, "audit")  # refresh the counts once the new lockfile is synced
        if kind == "npm" and task["rc"] == 1:  # npm exits 1 while anything is left that needs a major bump
            return "partly fixed %s (the rest need breaking upgrades, see log) · review with git diff" % rel
        if task["rc"] != 0:
            raise RuntimeError("fix failed (exit %s), see log" % task["rc"])
        return "fixed %s's lockfile · review with git diff" % rel

    def wait_for_sync(self, job):
        """Ask the menu bar app for fresh lockfiles (it checks in every 15s) and give it a minute."""
        with store.lock:
            sync = store.data.setdefault("project_sync", {})
            asked = sync["wanted"] = now()
        job.log("# asking the menu bar app for the lockfiles in " + str(projects_root()))
        for _ in range(60):
            if (sync.get("at") or 0) >= asked:
                break
            time.sleep(1)
        else:
            job.log("! the menu bar app didn't answer (is it running?), using the lockfiles it sent %s"
                    % (time.strftime("%Y-%m-%d %H:%M", time.localtime(sync["at"])) if sync.get("at") else "(none yet)"))
        if sync.get("error"):
            job.log("! menu bar app: " + sync["error"])

    def projects(self):
        """{(kind, project dir relative to the projects folder): (ecosystem, [(dep, version)], lockfile path, mtime)}"""
        out, root = {}, projects_root()
        for path, f in sorted((store.data.get("project_files") or {}).items()):
            if not path.startswith(str(root) + "/"):  # sent before the projects folder was changed
                continue
            kind, eco = LOCKFILES[os.path.basename(path)]
            try:
                text = (PROJECTS_DIR / f["file"]).read_text(errors="replace")
            except OSError:
                continue
            rel = os.path.relpath(os.path.dirname(path), root)
            try:
                deps = lock_deps(os.path.basename(path), text)
            except Exception as e:  # one unreadable lockfile mustn't stop the other projects' checks
                print("projects: skipping %s: %s: %s" % (path, type(e).__name__, e), flush=True)
                continue
            out[(kind, rel)] = (eco, deps, path, f["mtime"])
        return out

    def scan(self, job):
        self.wait_for_sync(job)
        projects, old = self.projects(), inv_pkgs(self.id)
        res, changed = [], set()
        for (kind, rel), (eco, deps, path, mtime) in projects.items():
            p = pkg(rel, "%d deps" % len(deps), None, kind, os.path.basename(path))
            p["lock_mtime"] = mtime
            if (old.get((kind, rel)) or {}).get("lock_mtime") != mtime:
                changed.add(rel)
            res.append(p)
        self.malware(job, projects, res, changed)
        return res

    def malware(self, job, projects, res, changed):
        by_eco = {}
        for (kind, rel), (eco, deps, _, _) in projects.items():
            by_eco.setdefault(eco, []).extend((n, v, rel, "installed") for n, v in deps)
        hits, have = [], set()

        def add(h):
            k = (h["id"], h["pkg"], h["version"], h["context"])
            if k not in have:
                have.add(k)
                hits.append(h)
        for eco, q in by_eco.items():
            job.log("# malware check: %d %s package versions against OSV" % (len(q), eco))
            try:
                for h in osv_malware(eco, q):
                    add(h)
            except Exception as e:
                job.log("! OSV malware check failed for %s: %s" % (eco, e))
        # Socket: a couple of lookups per scan (its free quota is small), changed projects first;
        # everything gets covered over the following scans and stays cached for a week
        budget = {"left": 2}
        for eco, q in by_eco.items():
            q.sort(key=lambda x: x[2] not in changed)
            try:
                sk = socket_alerts(job, eco, [(n, v, 7 * 86400) for n, v, _, _ in q], budget) or {}
            except Exception as e:
                job.log("! Socket check failed for %s: %s" % (eco, e))
                continue
            for n, v, ctx, where in q:
                for typ, _, action in sk.get((n, v)) or []:
                    if action == "error":
                        add({"id": "Socket: " + SOCKET_LABEL.get(typ, typ), "pkg": n, "version": v,
                             "context": ctx, "where": where})
        bad = {}
        for h in hits:
            bad.setdefault(h["context"], h["id"])
        for p in res:
            p["malware"] = bad.get(p["name"])
        record_flags(self, job, hits)

    def audit(self, job):
        self.wait_for_sync(job)
        return osv_audit(job, [(rel, eco, deps, "%s (%s)" % (rel, kind))
                               for (kind, rel), (eco, deps, _, _) in self.projects().items()])


def osv_audit(job, groups):
    """CVE findings from OSV for [(context, ecosystem, [(name, version)], label)]."""
    found, ids = [], set()
    for ctx, eco, deps, label in groups:
        for i in range(0, len(deps), 1000):
            chunk = deps[i:i + 1000]
            data = http_json("https://api.osv.dev/v1/querybatch", {"queries": [
                {"package": {"name": n, "ecosystem": eco}, "version": v} for n, v in chunk]}, timeout=120)
            for (n, v), r in zip(chunk, data.get("results", [])):
                vids = sorted((x["id"] for x in r.get("vulns") or [] if not x["id"].startswith("MAL-")),
                              key=lambda x: not x.startswith("GHSA"))  # GHSA ids carry a severity
                if vids:
                    found.append((ctx, eco, n, v, vids))
                    ids.update(vids)
        job.log("  %s: %d dependencies" % (label, len(deps)))
    job.log("# fetching %d advisories from OSV" % len(ids))
    order = sorted(ids)
    with concurrent.futures.ThreadPoolExecutor(16) as ex:  # docker images can mean thousands of distro advisories
        full = dict(zip(order, ex.map(osv_vuln, order)))
    res = []
    for ctx, eco, n, v, vids in found:
        seen = set()
        for vid in vids:
            if vid in seen:
                continue  # the same advisory under another id (GHSA vs PYSEC)
            o = full.get(vid) or {}
            # Debian DSA/DLA and Ubuntu USN notices bundle CVEs already listed one by one
            if o.get("upstream") and set(o["upstream"]) <= seen:
                continue
            seen.update([vid] + o.get("aliases", []) + o.get("upstream", []))
            res.append(finding(n, v, vid, osv_severity(o), o.get("summary") or o.get("details", ""),
                               osv_fix(o, n, eco), ctx, o.get("aliases", [])))
    return res


# ---------------------------------------------------------------- docker images

DOCKER_DIR = STATE_DIR / "docker"  # what each image contains, by image id (images never change, so read once)
# the files inside an image that say what's installed: OS package databases, Python dist-info, node_modules
DOCKER_WANT = re.compile(r"^(?:etc/os-release|usr/lib/os-release|var/lib/dpkg/status|var/lib/dpkg/status\.d/[^/]+"
                         r"|lib/apk/db/installed|.*/(?:site|dist)-packages/[^/]+\.dist-info/METADATA"
                         r"|(?:.*/)?node_modules/(?:@[^/]+/)?[^/]+/package\.json"
                         r"|.*/specifications/(?:default/)?[^/]+\.gemspec)$")
DOCKER_MAX_FILE = 16 << 20
DOCKER_CACHE_VERSION = 2  # raised when image_packages learns a new kind of package (2: Ruby gems), so images get reread


def layer_files(f):
    """One layer tarball: (wanted files {path: bytes}, deleted paths, emptied dirs). Nothing is written to disk."""
    files, gone, opaque = {}, [], []
    with tarfile.open(fileobj=f, mode="r|*") as t:
        for m in t:
            name = m.name
            while name.startswith("./"):
                name = name[2:]
            name = name.lstrip("/")
            d, base = os.path.split(name)
            if base == ".wh..wh..opq":
                opaque.append(d)
            elif base.startswith(".wh."):
                gone.append(os.path.join(d, base[4:]))
            elif m.isfile() and m.size <= DOCKER_MAX_FILE and DOCKER_WANT.match(name):
                files[name] = t.extractfile(m).read()
    return files, gone, opaque


def image_files(job, image_id, timeout=900):
    """The wanted files as the image's final filesystem has them, read from `docker save` as it streams.
    Layers are overlaid in order, honouring whiteouts; no container is started and nothing in the image runs."""
    job.log("$ docker save " + image_id)
    p = subprocess.Popen(["docker", "save", image_id],  # noqa: S607 - docker is wherever ENV's PATH finds it
                         env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    timer = threading.Timer(timeout, p.kill)
    timer.start()
    layers, manifest = {}, None
    try:
        with tarfile.open(fileobj=p.stdout, mode="r|") as outer:
            for m in outer:
                if not m.isfile():
                    continue
                f = outer.extractfile(m)
                if m.name == "manifest.json":
                    manifest = loads(f.read(), None)
                elif m.name.startswith("blobs/") or m.name.endswith("/layer.tar"):
                    try:
                        layers[m.name] = layer_files(f)
                    except tarfile.TarError:
                        pass  # image config / OCI manifest blobs, not layers
    finally:
        timer.cancel()
        err = p.stderr.read().decode(errors="replace")
        rc = p.wait()
    if rc != 0 or not manifest:
        raise RuntimeError("docker save %s failed: %s" % (image_id[:19], err.strip()[-300:] or "exit %s" % rc))
    fs = {}
    for name in manifest[0].get("Layers") or []:
        files, gone, opaque = layers.get(name) or ({}, [], [])
        for d in opaque:
            fs = {k: v for k, v in fs.items() if not k.startswith(d + "/")}
        for g in gone:
            fs = {k: v for k, v in fs.items() if k != g and not k.startswith(g + "/")}
        fs.update(files)
    return fs


def os_release(fs):
    text = (fs.get("etc/os-release") or fs.get("usr/lib/os-release") or b"").decode(errors="replace")
    return dict((k, v.strip().strip('"')) for k, _, v in (l.partition("=") for l in text.splitlines()) if v)


def os_ecosystem(osr):
    """OSV's name for the image's distro release, if OSV tracks it."""
    dist, ver = osr.get("ID", ""), osr.get("VERSION_ID", "")
    if dist == "debian" and ver:
        return "Debian:" + ver.split(".")[0]
    if dist == "ubuntu" and ver:
        major, _, minor = ver.partition(".")
        return "Ubuntu:%s%s" % (ver, ":LTS" if minor == "04" and major.isdigit() and int(major) % 2 == 0 else "")
    if dist == "alpine" and ver:
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    return None


def image_packages(fs):
    """(distro label, [(ecosystem, name, version)]) from an image's files. Distro packages are named by
    source package (Debian/Ubuntu) or origin (Alpine), which is what OSV's advisories use."""
    osr = os_release(fs)
    os_eco = os_ecosystem(osr)
    label = " ".join(x for x in (osr.get("ID"), osr.get("VERSION_ID")) if x) or "no package database"
    res = set()
    for path, data in fs.items():
        text = data.decode(errors="replace")
        if path == "var/lib/dpkg/status" or path.startswith("var/lib/dpkg/status.d/"):
            for para in text.split("\n\n"):
                f = dict(re.findall(r"(?m)^([A-Za-z-]+): ?(.*)$", para))
                if not f.get("Package") or not f.get("Version"):
                    continue
                if "Status" in f and not f["Status"].endswith(" installed"):
                    continue
                src = re.match(r"(\S+)(?: \((\S+)\))?", f.get("Source") or f["Package"])
                if os_eco:
                    res.add((os_eco, src.group(1), src.group(2) or f["Version"]))
        elif path == "lib/apk/db/installed":
            for block in text.split("\n\n"):
                f = dict(l.split(":", 1) for l in block.splitlines() if len(l) > 2 and l[1] == ":")
                if f.get("P") and f.get("V") and os_eco:
                    res.add((os_eco, f.get("o") or f["P"], f["V"]))
        elif path.endswith("/METADATA"):
            n = re.search(r"(?m)^Name: *(\S+)", text)
            v = re.search(r"(?m)^Version: *(\S+)", text)
            if n and v:
                res.add(("PyPI", n.group(1), v.group(1)))
        elif path.endswith(".gemspec"):  # "specifications/nokogiri-1.16.0-x86_64-linux.gemspec"
            m = re.match(r"(.+)-([0-9][^-]*)(?:-[^/]+)?\.gemspec$", os.path.basename(path))
            if m:
                res.add(("RubyGems", m.group(1), m.group(2)))
        elif path.endswith("package.json"):
            d = loads(text, {})
            if isinstance(d, dict) and isinstance(d.get("name"), str) and isinstance(d.get("version"), str):
                res.add(("npm", d["name"], d["version"]))
    return label, sorted(res)


class Docker(Manager):
    id, label, icon, color = "docker", "docker images", "layers", "blue"
    desc = ("Images in the local Docker engine (OrbStack / Docker Desktop): the OS packages, Python, npm and Ruby "
            "packages inside each one, checked for malware and CVEs. Read from `docker save`, so no container is started")
    actions = ("scan", "audit")
    separate = True  # images aren't installed tools; kept out of the headline totals (malware still counts)
    unit = "images"
    ignore_key = "docker_ignore"

    def available(self):
        return bool(which("docker"))

    def images(self, job):
        """[(ref, image id, created)] or None if the Docker engine isn't running."""
        rc, out = job.run(["docker", "image", "ls", "--no-trunc", "--format", "{{json .}}"], quiet=True, timeout=60)
        if rc != 0:
            return None
        res = []
        for d in iter_json(out):
            iid = d.get("ID") or ""
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", iid):
                continue
            repo, tag = d.get("Repository") or "<none>", d.get("Tag") or "<none>"
            ref = "%s:%s" % (repo, tag) if repo != "<none>" else "<untagged> " + iid[7:19]
            res.append((ref, iid, (d.get("CreatedAt") or "")[:10]))
        return res

    def containers(self, job):
        """{image id: (running, all)} container counts."""
        _, out = job.run(["docker", "container", "ls", "-a", "-q", "--no-trunc"], quiet=True, timeout=60)
        ids = [i for i in out.split() if re.fullmatch(r"[0-9a-f]{64}", i)]
        counts = {}
        if ids:
            _, out = job.run(["docker", "container", "inspect", "--format", "{{.Image}} {{.State.Running}}"] + ids,
                             quiet=True, timeout=60)
            for line in out.splitlines():
                iid, _, running = line.partition(" ")
                r, a = counts.get(iid, (0, 0))
                counts[iid] = (r + (running == "true"), a + 1)
        return counts

    def contents(self, job, iid, ref):
        """(distro label, [(ecosystem, name, version)]) for an image id, read once and cached."""
        path = DOCKER_DIR / (iid[7:] + ".json")
        cached = loads(path.read_text(), None) if path.exists() else None
        if cached and cached.get("v") == DOCKER_CACHE_VERSION:
            return cached["os"], [tuple(x) for x in cached["packages"]]
        job.log("# reading %s (%s)" % (ref, iid[7:19]))
        t0 = now()
        label, pkgs = image_packages(image_files(job, iid))
        job.log("  %s: %s, %d packages (%.0fs)" % (ref, label, len(pkgs), now() - t0))
        DOCKER_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"v": DOCKER_CACHE_VERSION, "os": label, "packages": pkgs}))
        return label, pkgs

    def scan(self, job):
        imgs = self.images(job)
        if imgs is None:  # engine stopped: keep showing the last scan rather than reporting everything removed
            self.hold = "Docker isn't running (start OrbStack or Docker Desktop), so this is the last scan"
            job.log("! " + self.hold)
            return [dict(p) for p in inv_pkgs(self.id).values()]
        self.hold = None
        counts = self.containers(job)
        res, by_eco = [], {}
        for ref, iid, created in imgs:
            try:
                label, pkgs = self.contents(job, iid, ref)
            except Exception as e:
                job.log("! couldn't read %s: %s" % (ref, e))
                continue
            running, total = counts.get(iid, (0, 0))
            use = ("%d running / %d containers" % (running, total)) if total else "no containers"
            p = pkg(ref, "%d pkgs" % len(pkgs), None, label, "built %s · %s · %s" % (created, use, iid[7:19]))
            p["running"] = running
            res.append(p)
            for eco, n, v in pkgs:
                if eco in ("PyPI", "npm", "RubyGems"):  # OSV's malicious-packages list only covers registries
                    by_eco.setdefault(eco, []).append((n, v, ref, "installed"))
        live = {iid[7:] + ".json" for _, iid, _ in imgs}
        for f in DOCKER_DIR.glob("*.json") if DOCKER_DIR.exists() else []:
            if f.name not in live:
                f.unlink()  # image deleted
        hits, ok = [], True
        for eco, q in by_eco.items():
            job.log("# malware check: %d %s package versions against OSV" % (len(q), eco))
            try:
                hits += osv_malware(eco, q)
            except Exception as e:
                ok = False
                job.log("! OSV malware check failed for %s: %s" % (eco, e))
        if ok:
            bad = {}
            for h in hits:
                bad.setdefault(h["context"], h["id"])
            for p in res:
                p["malware"] = bad.get(p["name"])
            record_flags(self, job, hits)
        return res

    def audit(self, job):
        imgs = self.images(job)
        if imgs is None:
            raise RuntimeError("Docker isn't running (start OrbStack or Docker Desktop)")
        groups = []
        for ref, iid, _ in imgs:
            try:
                label, pkgs = self.contents(job, iid, ref)
            except Exception as e:
                job.log("! couldn't read %s: %s" % (ref, e))
                continue
            by_eco = {}
            for eco, n, v in pkgs:
                by_eco.setdefault(eco, []).append((n, v))
            groups += [(ref, eco, deps, "%s %s" % (ref, eco)) for eco, deps in sorted(by_eco.items())]
        return osv_audit(job, groups)


DISCOVER = [
    ("pipx", ["pipx", "list", "--short"], r"^(\S+) (\S+)"),
    ("pnpm", ["pnpm", "ls", "-g", "--depth=0", "--parseable"], None),
    ("yarn", ["yarn", "global", "list"], r'info "(.+)@([^@"]+)" has binaries'),
    ("mas", ["mas", "list"], r"^\d+\s+(.+?)\s+\(([^)]+)\)"),
    ("conda", ["conda", "env", "list"], r"^(\S+)\s+\S*\s*(/\S+)"),
]


class Other(Manager):
    id, label, icon, color = "other", "other binaries", "bin", "muted"
    desc = "Manual installs, app-bundled CLIs and any untracked package managers on PATH"
    actions = ("scan",)

    def scan(self, job):
        res = []
        for d in (HOME / ".local/bin", Path("/usr/local/bin")):
            if not d.is_dir():
                continue
            for f in sorted(d.iterdir()):
                target = os.path.realpath(f)
                if "/uv/tools/" in target or "/uv/python/" in target or "/fnm/" in target:
                    continue
                if target.startswith("/Applications/") or "/Library/Application Support/" in target:
                    kind = "app-bundled"
                elif "/versions/" in target:
                    kind = "self-updating"
                else:
                    kind = "manual"
                res.append(pkg(f.name, "-", None, kind, target if target != str(f) else str(f)))
        for tool, cmd, rx in DISCOVER:
            if not which(tool):
                continue
            _, out = job.run(cmd, quiet=True, timeout=120)
            items = re.findall(rx, out, re.M) if rx else [(os.path.basename(l), "-") for l in out.splitlines()[1:] if l.strip()]
            for name, ver in items:
                res.append(pkg(name, ver, None, tool, "untracked manager: %s" % tool))
        bun = HOME / ".bun/install/global/package.json"
        if bun.exists():
            for name, ver in loads(bun.read_text(), {}).get("dependencies", {}).items():
                res.append(pkg(name, ver, None, "bun", "untracked manager: bun"))
        return res


MANAGERS = [Uv(), Npm(), Brew(), Pip(), Go(), Cargo(), Gem(), Projects(), Docker(), Other()]
MANAGER_BY_ID = {m.id: m for m in MANAGERS}
runner = Runner()


# ---------------------------------------------------------------- scheduler

def scheduler():
    time.sleep(5)
    while True:
        try:
            s, sch = store["settings"], store["schedule"]
            for action in ("scan", "audit", "update"):
                hours = float(s.get("%s_every_hours" % action) or 0)
                # nothing runs on its own until setup has picked the managers
                if s.get("setup_done") and hours > 0 and now() - sch.get(action, 0) >= hours * 3600:
                    sch[action] = now()
                    store.save()
                    runner.enqueue("all", action, trigger="schedule")
        except Exception:
            traceback.print_exc()
        time.sleep(60)


def next_runs():
    s, sch, out = store["settings"], store["schedule"], {}
    for action in ("scan", "audit", "update"):
        hours = float(s.get("%s_every_hours" % action) or 0)
        out[action] = (sch.get(action, 0) + hours * 3600) if hours > 0 else None
    return out


# ---------------------------------------------------------------- api

def log_tail(job_id):
    """Last meaningful log line of a running job, shown under its progress bar."""
    f = LOG_DIR / (job_id + ".log")
    try:
        with open(f, "rb") as fh:
            fh.seek(max(0, f.stat().st_size - 4096))
            lines = [l.strip() for l in fh.read().decode("utf-8", "replace").splitlines() if l.strip()]
    except OSError:
        return ""
    return lines[-1][:160] if lines else ""


def state_payload():
    managers, totals = [], {"packages": 0, "outdated": 0, "vulns": 0, "high": 0, "malware": 0}
    busy = {}
    for j in store["jobs"]:
        if j["state"] in ("queued", "running"):
            busy.setdefault(j["manager"], []).append(j["action"])
    week = now() - 7 * 86400
    new7 = sum(1 for mid, inv in store["inventory"].items() for p in inv.get("packages", [])
               if p.get("first_seen", 0) >= week and not getattr(MANAGER_BY_ID.get(mid), "separate", False))
    choices = []  # every manager, for the setup screen
    for m in MANAGERS:
        d = m.meta()
        choices.append({k: d[k] for k in ("id", "label", "desc", "icon", "available")} | {"enabled": enabled(m)})
        if not enabled(m):
            continue
        inv = store["inventory"].get(m.id) or {}
        vul = store["vulns"].get(m.id) or {}
        pk, fs = inv.get("packages", []), vul.get("findings", [])
        mal = (store["malware"].get(m.id) or {}).get("hits", [])
        if m.separate:  # projects marked ignored (deliberate targets etc.) don't count
            ign = m.ignored()
            fs = [f for f in fs if f["context"] not in ign]
            mal = [h for h in mal if h["context"] not in ign]
        updatable = "update" in m.actions and not m.hold  # pip: shown, never updated, so no cooldown either
        d.update(malware=[h for h in mal if h["where"] == "installed"], osv=bool(m.osv_eco),
                 malware_checked_at=(store["malware"].get(m.id) or {}).get("checked_at"),
                 cooling=sum(updatable and cooldown_left(p) > 0 and not p.get("blocked") for p in pk),
                 blocked=sum(bool(p.get("blocked")) for p in pk))
        totals["malware"] += len(d["malware"])
        d.update(count=len(pk), outdated=sum(p["outdated"] for p in pk), vulns=len(fs),
                 high=sum(SEV_RANK[f["severity"]] >= 3 for f in fs),
                 scanned_at=inv.get("scanned_at"), audited_at=vul.get("audited_at"),
                 busy=busy.get(m.id, []))
        managers.append(d)
        if m.separate:
            continue
        totals["packages"] += d["count"]
        totals["outdated"] += d["outdated"]
        totals["vulns"] += d["vulns"]
        totals["high"] += d["high"]
    day = now() - 86400
    jobs24 = [j for j in store["jobs"] if j["queued"] >= day]
    totals.update(new7=new7, jobs24=len(jobs24), failed24=sum(j["state"] == "failed" for j in jobs24))
    return {
        "host": socket.gethostname().split(".")[0], "user": getpass.getuser(),
        "addr": "%s:%d" % (HOST, PORT), "uptime": now() - STARTED, "now": now(),
        "managers": managers, "manager_choices": choices, "totals": totals,
        "jobs": [dict(j, step=log_tail(j["id"])) if j["state"] == "running" else j
                 for j in reversed(store["jobs"][-60:])],
        "events": list(reversed(store["events"][-80:])),
        "unread": sum(not e["read"] for e in store["events"]),
        "settings": store["settings"], "next": next_runs(),
        "socket": {"org": store.data.get("socket_org"), "quota": store.data.get("socket_quota")},
        "projects": dict({k: v for k, v in (store.data.get("project_sync") or {}).items() if k != "mtimes"},
                         ignored=sorted(store.data.get("project_ignore") or []),
                         tasks=[{k: t[k] for k in ("id", "kind", "path", "pkgs")} for t in list(project_tasks.values())
                                if "rc" not in t]),
        "docker": {"ignored": sorted(store.data.get("docker_ignore") or [])},
        "state_dir": str(STATE_DIR),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "pkgdash"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _hosts(self):
        return ("%s:%d" % (HOST, PORT), "localhost:%d" % PORT)

    def _host_ok(self):
        # DNS-rebinding guard: only answer to our own loopback names
        return self.headers.get("Host", "").lower() in self._hosts()

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        u = urlparse(self.path)
        parts = [p for p in u.path.split("/") if p]
        if u.path in ("/", "/index.html"):
            html = (APP_DIR / "index.html").read_text().replace("__PKGDASH_TOKEN__", TOKEN)
            return self._send(200, html, "text/html; charset=utf-8")
        if u.path == "/api/state":
            return self._send(200, state_payload())
        on = {m.id for m in MANAGERS if enabled(m)}
        if u.path == "/api/inventory":
            return self._send(200, {k: v.get("packages", []) for k, v in store["inventory"].items() if k in on})
        if u.path == "/api/vulns":
            return self._send(200, {k: v.get("findings", []) for k, v in store["vulns"].items() if k in on})
        if u.path == "/api/socket":  # the setup screen: is a token saved? (reading the Keychain is slow-ish)
            return self._send(200, {"has_token": bool(keychain_socket_token()), "org": store.data.get("socket_org")})
        if u.path == "/api/advisory":  # an OSV record, for the malware banner's details drawer
            vid = parse_qs(u.query).get("id", [""])[0]
            if not re.fullmatch(r"[A-Z][A-Za-z0-9]*-[A-Za-z0-9._-]+", vid):
                return self._send(400, {"error": "bad id"})
            try:
                o = osv_vuln(vid)
            except Exception as e:
                return self._send(502, {"error": "OSV lookup failed: %s" % e})
            return self._send(200, {k: o.get(k) for k in ("id", "summary", "details", "aliases", "published",
                                                         "modified", "affected", "references")})
        if len(parts) == 3 and parts[:2] == ["api", "job"]:
            jid = parts[2]
            if not re.fullmatch(r"[\w-]+", jid):
                return self._send(400, {"error": "bad id"})
            off = int(parse_qs(u.query).get("offset", ["0"])[0] or 0)
            f = LOG_DIR / (jid + ".log")
            rec = next((j for j in store["jobs"] if j["id"] == jid), None)
            text = ""
            if f.exists():
                with open(f, "rb") as fh:
                    fh.seek(off)
                    raw = fh.read()
                text, off = raw.decode("utf-8", "replace"), off + len(raw)
            return self._send(200, {"job": rec, "text": text, "offset": off})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok() or not secrets.compare_digest(self.headers.get("X-Pkgdash-Token") or "", TOKEN):
            return self._send(403, {"error": "forbidden"})
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in ["http://" + h for h in self._hosts()]:
            return self._send(403, {"error": "bad origin"})
        n = int(self.headers.get("Content-Length") or 0)
        body = loads(self.rfile.read(n).decode() if n else "{}", {})
        path = urlparse(self.path).path
        if path == "/api/run":
            mid, action = body.get("manager"), body.get("action")
            if action not in ("scan", "audit", "update") or (mid != "all" and mid not in MANAGER_BY_ID):
                return self._send(400, {"error": "bad request"})
            if mid != "all" and not enabled(MANAGER_BY_ID[mid]):
                return self._send(400, {"error": "%s is turned off in setup" % mid})
            only = None
            if body.get("pkg") is not None:
                # single-package update: only names a scan found, so nothing user-typed reaches a command line
                only = (body.get("kind"), body.get("pkg"))
                known = {(p["kind"], p["name"]) for p in (store["inventory"].get(mid) or {}).get("packages", [])}
                if action != "update" or only not in known:
                    return self._send(400, {"error": "unknown package"})
            force = bool(only and body.get("force") is True)
            return self._send(200, {"queued": runner.enqueue(mid, action, only=only, force=force)})
        if path == "/api/settings":
            s = store["settings"]
            root = clean_projects_root(body["projects_root"]) if "projects_root" in body else s["projects_root"]
            if root is None:
                return self._send(400, {"error": "the projects folder has to be inside your home folder (not ~/Library)"})
            for k, v in body.items():
                if k in DEFAULT_SETTINGS and type(v) in (int, float, bool) and type(DEFAULT_SETTINGS[k]) in (int, float, bool):
                    s[k] = bool(v) if isinstance(DEFAULT_SETTINGS[k], bool) else max(0, float(v))
            if isinstance(body.get("disabled_managers"), list):
                s["disabled_managers"] = sorted({m for m in body["disabled_managers"] if m in MANAGER_BY_ID})
            s["projects_root"] = root
            store.save()
            return self._send(200, s)
        if path == "/api/socket":  # the setup screen saving + testing the Socket.dev token, or removing it
            if body.get("clear") is True:
                delete_socket_token()
                store["socket_org"] = None
                store.save()
                return self._send(200, {"has_token": False, "org": None})
            token = body.get("token")
            token = token.strip() if isinstance(token, str) else keychain_socket_token()  # no token = test the saved one
            if not token or not SOCKET_TOKEN_RE.fullmatch(token):
                return self._send(400, {"error": "that doesn't look like a Socket.dev API token"})
            try:
                orgs = json.loads(socket_api(token, "organizations")).get("organizations") or {}
            except urllib.error.HTTPError as e:
                return self._send(400, {"error": "Socket.dev refused the token (HTTP %d)" % e.code})
            except (OSError, ValueError) as e:
                return self._send(502, {"error": "couldn't reach Socket.dev: %s" % e})
            if not orgs:
                return self._send(400, {"error": "the token works, but it isn't in a Socket.dev organization"})
            if isinstance(body.get("token"), str):
                try:
                    save_socket_token(token)
                except (OSError, ValueError, subprocess.SubprocessError) as e:
                    return self._send(500, {"error": str(e)})
            store["socket_org"] = next(iter(orgs.values()))["slug"]
            store.save()
            return self._send(200, {"has_token": True, "org": store["socket_org"]})
        if path == "/api/projects/sync":
            return self._send(200, projects_sync(body))
        if path == "/api/projects/task":  # the menu bar app reporting a lockfile fix it ran
            task = project_tasks.get(str(body.get("id")))
            if not task or not isinstance(body.get("rc"), int):
                return self._send(400, {"error": "unknown task"})
            task.update(output=str(body.get("output") or "")[-20000:], rc=body["rc"])
            return self._send(200, {"ok": True})
        if path == "/api/projects/ignore":  # projects and docker images
            m = MANAGER_BY_ID.get(body.get("manager") or "projects")
            if not m or not m.ignore_key:
                return self._send(400, {"error": "unknown manager"})
            names = {p["name"] for p in (store["inventory"].get(m.id) or {}).get("packages", [])}
            name = body.get("name")
            if name not in names:
                return self._send(400, {"error": "unknown " + m.unit.rstrip("s")})
            with store.lock:
                ign = set(store.data.get(m.ignore_key) or [])
                ign.add(name) if body.get("ignore") is True else ign.discard(name)
                store[m.ignore_key] = sorted(ign)
                store.save()
            return self._send(200, {"ignored": store[m.ignore_key]})
        if path == "/api/events/read":
            with store.lock:
                for e in store["events"]:
                    e["read"] = True
                store.save()
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})


httpd = None  # the loopback server


def main():
    global httpd
    threading.Thread(target=scheduler, daemon=True).start()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    httpd.daemon_threads = True
    print("pkgdash on http://%s:%d" % (HOST, PORT), flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
