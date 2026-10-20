"""pkgdash with made-up data: for trying the dashboard and for the README's screenshots.

    /usr/bin/python3 -I demo.py        # → http://127.0.0.1:7890 (PKGDASH_PORT to change it)

It runs the real server, but nothing is scanned, installed or sent anywhere: jobs are switched off,
every manager reports itself as present, and the state lives in a temporary folder that's deleted
when you stop it. The packages are real-world names; the versions and findings are illustrative.
"""
import os
import random
import shutil
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="pkgdash-demo-")
os.environ.update(HOME=TMP, USER="alex", LOGNAME="alex", PKGDASH_PORT=os.environ.get("PKGDASH_PORT", "7890"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server as S  # noqa: E402  (after HOME points at the temporary folder)

NOW = time.time()
DAY = 86400
rng = random.Random(7)  # noqa: S311 - made-up demo numbers


def pkgs(mid, rows, kind=""):
    """rows: (name, version, latest or None, days since its release, new this week?)"""
    out = []
    for name, ver, latest, age, new in rows:
        p = S.pkg(name, ver, latest, kind, "")
        p["first_seen"] = NOW - rng.randint(1, 5) * DAY if new else 0
        if latest:
            p["released"] = NOW - age * DAY
        out.append(p)
    return {"scanned_at": NOW - rng.randint(20, 70) * 60, "packages": out}


def row(name, ver, latest=None, age=30, new=False):
    return (name, ver, latest, age, new)


INVENTORY = {
    "uv": pkgs("uv", [row("ruff", "0.6.9", "0.7.1", 2), row("black", "24.8.0", "24.10.0", 18), row("httpie", "3.2.3"),
                      row("pre-commit", "4.0.1"), row("mypy", "1.13.0"), row("yt-dlp", "2024.10.7", "2024.10.22", 1),
                      row("poetry", "1.8.4"), row("ansible-core", "2.17.5", new=True)], "tool"),
    "npm": pkgs("npm", [row("npm", "10.9.0"), row("pnpm", "9.12.1", "9.12.3", 3), row("typescript", "5.6.3"),
                        row("eslint", "9.12.0", "9.13.0", 6), row("prettier", "3.3.3"), row("vercel", "37.12.1", "37.14.0", 2),
                        row("tsx", "4.19.1"), row("npm-check-updates", "17.1.4", new=True)], "global"),
    "brew": pkgs("brew", [row(n, v, l, a) for n, v, l, a in [
        ("git", "2.47.0", None, 0), ("curl", "8.10.1", None, 0), ("openssl@3", "3.3.2", "3.4.0", 4),
        ("python@3.12", "3.12.7", None, 0), ("node", "22.9.0", "23.1.0", 9), ("ffmpeg", "7.1", None, 0),
        ("jq", "1.7.1", None, 0), ("ripgrep", "14.1.1", None, 0), ("fd", "10.2.0", None, 0), ("bat", "0.24.0", None, 0),
        ("htop", "3.3.0", None, 0), ("wget", "1.24.5", None, 0), ("gnupg", "2.4.5", "2.4.6", 2), ("sqlite", "3.46.1", "3.47.0", 7),
        ("postgresql@16", "16.4", None, 0), ("redis", "7.2.5", "7.4.1", 12), ("cmake", "3.30.5", None, 0), ("tmux", "3.5a", None, 0),
        ("neovim", "0.10.2", None, 0), ("fzf", "0.55.0", "0.56.0", 1), ("gh", "2.59.0", None, 0), ("awscli", "2.18.10", "2.18.14", 3),
        ("terraform", "1.9.8", None, 0), ("kubernetes-cli", "1.31.1", None, 0), ("helm", "3.16.2", None, 0),
        ("libpng", "1.6.44", None, 0), ("xz", "5.6.3", None, 0), ("zstd", "1.5.6", None, 0)]]
        + [row("visual-studio-code", "1.94.2", "1.95.0", 2), row("firefox", "131.0.3", None), row("iterm2", "3.5.6", None),
           row("rectangle", "0.84", None), row("obsidian", "1.7.4", None)], "formula"),
    "pip": pkgs("pip", [row("pip", "24.2"), row("setuptools", "75.1.0"), row("wheel", "0.44.0"), row("requests", "2.28.2"),
                        row("urllib3", "1.26.15"), row("jinja2", "3.1.2"), row("certifi", "2024.8.30"), row("six", "1.16.0")], "python3.12"),
    "go": pkgs("go", [row("gopls", "v0.16.2"), row("golangci-lint", "v1.61.0"), row("staticcheck", "2024.1.1"), row("dlv", "v1.23.1")], "bin"),
    "cargo": pkgs("cargo", [row("cargo-edit", "0.13.0"), row("cargo-watch", "8.5.3"), row("tokei", "12.1.2"), row("bottom", "0.10.2")], "crate"),
    "gem": pkgs("gem", [row("rubocop", "1.66.1", "1.67.0", 4), row("bundler", "2.5.21"), row("cocoapods", "1.15.2"),
                        row("rake", "13.2.1"), row("json", "2.7.2")], "gem"),
    "other": pkgs("other", [row("bun", "1.1.30"), row("deno", "2.0.2"), row("ollama", "0.3.14")], "bin"),
}

for p in INVENTORY["brew"]["packages"]:  # the apps are casks, not formulae
    if p["name"] in ("visual-studio-code", "firefox", "iterm2", "rectangle", "obsidian"):
        p["kind"] = "cask"

PROJECTS = [("npm", "web/storefront", 642, "package-lock.json"), ("npm", "web/admin-panel", 588, "package-lock.json"),
            ("uv", "api/orders-service", 74, "uv.lock"), ("uv", "tools/report-builder", 31, "uv.lock"),
            ("cargo", "cli/logtail", 112, "Cargo.lock"), ("npm", "experiments/chat-widget", 391, "yarn.lock"),
            ("uv", "scripts/backup", 9, "requirements.txt"), ("cargo", "games/tetris-rs", 48, "Cargo.lock"),
            ("bundler", "web/marketing-site", 87, "Gemfile.lock")]
proj = []
for kind, rel, deps, lock in PROJECTS:
    p = S.pkg(rel, "%d deps" % deps, None, "yarn" if lock == "yarn.lock" else kind, lock)
    p["first_seen"] = 0
    proj.append(p)
INVENTORY["projects"] = {"scanned_at": NOW - 40 * 60, "packages": proj}

F = S.finding
VULNS = {
    "uv": [],
    "npm": [F("semver", "7.5.1", "GHSA-c2qf-rxjj-qqgw", "medium", "semver vulnerable to Regular Expression Denial of Service",
              "7.5.2", "npm-check-updates")],
    "brew": [F("curl", "8.3.0", "CVE-2023-38545", "high", "SOCKS5 heap buffer overflow", "8.4.0", "curl (build dependency of git)"),
             F("redis", "7.2.5", "CVE-2024-31449", "high", "Lua bit library stack overflow", "7.4.1", "redis"),
             F("sqlite", "3.46.1", "CVE-2024-0232", "medium", "use-after-free in JSON parser", "3.47.0", "sqlite")],
    "pip": [F("requests", "2.28.2", "CVE-2023-32681", "medium", "Proxy-Authorization header leaked on redirect to HTTPS", "2.31.0", "python3.12"),
            F("urllib3", "1.26.15", "CVE-2023-43804", "high", "Cookie request header isn't stripped during cross-origin redirects", "1.26.17", "python3.12"),
            F("jinja2", "3.1.2", "CVE-2024-22195", "medium", "HTML attribute injection when passing user input as keys to xmlattr", "3.1.3", "python3.12")],
    "go": [F("golang.org/x/net", "v0.15.0", "CVE-2023-44487", "high", "HTTP/2 rapid reset can cause excessive work", "v0.17.0", "dlv")],
    "cargo": [],
    "gem": [F("rexml", "3.3.8", "CVE-2024-49761", "high", "ReDoS when parsing a hex numeric character reference", "3.3.9", "rexml")],
    "other": [],
    "projects": [F("lodash", "4.17.15", "CVE-2020-8203", "high", "Prototype pollution in zipObjectDeep", "4.17.19", "web/admin-panel"),
                 F("minimist", "1.2.5", "CVE-2021-44906", "critical", "Prototype pollution", "1.2.6", "web/admin-panel"),
                 F("semver", "7.5.1", "CVE-2022-25883", "medium", "Regular Expression Denial of Service", "7.5.2", "web/storefront"),
                 F("tough-cookie", "4.1.2", "CVE-2023-26136", "medium", "Prototype pollution in cookie memstore", "4.1.3", "experiments/chat-widget"),
                 F("time", "0.1.45", "RUSTSEC-2020-0071", "medium", "Potential segfault in the time crate", "0.2.23", "cli/logtail")],
}

JOBS, n = [], 0
for mid, action, ago, state, summary in [
        ("all", "scan", 50, "done", ""), ("brew", "scan", 48, "done", "33 packages · 9 outdated"),
        ("npm", "audit", 47, "done", "1 vulnerability"), ("pip", "audit", 47, "done", "3 vulnerabilities"),
        ("brew", "update", 30, "done", "updated 4 · held 5 in cooldown"), ("go", "audit", 46, "done", "1 vulnerability"),
        ("projects", "audit", 26, "done", "5 vulnerabilities in 4 projects"), ("cargo", "update", 12, "failed", "cargo install-update: network error")]:
    n += 1
    if mid == "all":
        continue
    t = NOW - ago * 60
    JOBS.append({"id": "demo-%02d" % n, "manager": mid, "action": action, "trigger": "schedule" if n % 2 else "manual",
                 "pkg": None, "kind": None, "queued": t, "started": t, "ended": t + rng.randint(8, 140),
                 "state": state, "summary": summary})

EVENTS = [{"id": "e%d" % i, "ts": NOW - h * 3600, "kind": k, "manager": m, "text": t, "read": i > 2}
          for i, (h, k, m, t) in enumerate([
              (1, "new_vuln", "pip", "urllib3 1.26.15: CVE-2023-43804 (high)"),
              (2, "new_pkg", "npm", "new global package: npm-check-updates 17.1.4"),
              (3, "job_failed", "cargo", "cargo update failed: network error"),
              (20, "new_pkg", "uv", "new tool: ansible-core 2.17.5"),
              (30, "new_vuln", "brew", "redis 7.2.5: CVE-2024-31449 (high)")])]

with S.store.lock:
    S.store["inventory"] = INVENTORY
    S.store["vulns"] = {k: {"audited_at": NOW - rng.randint(30, 300) * 60, "findings": v} for k, v in VULNS.items()}
    S.store["malware"] = {k: {"checked_at": NOW - rng.randint(30, 300) * 60, "hits": []} for k in INVENTORY}
    S.store["jobs"] = JOBS
    S.store["events"] = EVENTS
    S.store["settings"].update(setup_done=True, projects_root="~/code", disabled_managers=["docker"])
    S.store["schedule"] = {"scan": NOW - 50 * 60, "audit": NOW - 4.8 * 3600}
    S.store.data["project_sync"] = {"at": NOW - 60, "files": len(PROJECTS), "error": None}
    S.store.data["socket_org"] = "acme"
    S.store.save()

# no real work: nothing queued, every manager present, no Keychain, a generic machine name
S.runner.enqueue = lambda *a, **k: []
for m in S.MANAGERS:
    m.available = lambda: True
S.keychain_socket_token = lambda: "demo-token"
_state = S.state_payload
S.state_payload = lambda: dict(_state(), host="macbook", state_dir="/Users/alex/.local/share/pkgdash")

if __name__ == "__main__":
    try:
        S.main()
    except KeyboardInterrupt:
        pass
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
