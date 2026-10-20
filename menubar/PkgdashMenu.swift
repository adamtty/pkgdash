// pkgdash menu bar item: left-click opens the dashboard, right-click shows a quick menu.
// Built by ../install.sh with swiftc (no Xcode project needed).
import AppKit

let base = "http://127.0.0.1:7878"

final class App: NSObject, NSApplicationDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    var state: [String: Any]?
    var token: String?

    func applicationDidFinishLaunching(_ n: Notification) {
        guard let b = item.button else { return }
        b.imagePosition = .imageLeading
        b.target = self
        b.action = #selector(clicked)
        b.sendAction(on: [.leftMouseUp, .rightMouseUp])
        setIcon("shippingbox", "")
        refresh()
        Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in self?.refresh() }
    }

    // MARK: status

    func setIcon(_ symbol: String, _ title: String) {
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "pkgdash")
        img?.isTemplate = true
        item.button?.image = img
        item.button?.title = title.isEmpty ? "" : " " + title
    }

    var totals: [String: Int] { (state?["totals"] as? [String: Any])?.compactMapValues { ($0 as? NSNumber)?.intValue } ?? [:] }
    var managers: [[String: Any]] { (state?["managers"] as? [[String: Any]])?.filter { $0["available"] as? Bool == true } ?? [] }
    var activeJobs: [[String: Any]] {
        (state?["jobs"] as? [[String: Any]] ?? []).filter { ["running", "queued"].contains($0["state"] as? String ?? "") }
    }

    func refresh() {
        URLSession.shared.dataTask(with: URL(string: base + "/api/state")!) { data, _, _ in
            let s = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            DispatchQueue.main.async { self.state = s; self.redraw(); self.maybeSyncProjects(); self.runProjectFixes() }
        }.resume()
    }

    // MARK: projects (the service runs under launchd, which macOS won't let read folders like ~/Documents,
    // so this app finds the lockfiles in the projects folder chosen on the setup screen and sends them over)

    var settings: [String: Any] { state?["settings"] as? [String: Any] ?? [:] }
    var projectsOn: Bool { !(settings["disabled_managers"] as? [String] ?? []).contains("projects") }
    /// "~/…" from the service, which only accepts folders inside the home folder; anything else falls back
    var projectsRoot: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let s = settings["projects_root"] as? String ?? ""
        guard s.hasPrefix("~/"), !s.split(separator: "/").contains("..") else { return home.appendingPathComponent("Documents") }
        return home.appendingPathComponent(String(s.dropFirst(2))).standardized
    }
    var rootLabel: String { projectsRoot.path.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~") }

    let lockNames: Set<String> = ["package-lock.json", "yarn.lock", "uv.lock", "poetry.lock", "Cargo.lock", "requirements.txt"]
    let skipDirs: Set<String> = ["node_modules", "Library", "venv", "env", "target", "dist", "build", "__pycache__", "Pods", "vendor"]
    let syncQueue = DispatchQueue(label: "pkgdash.projects")
    var lastSync = Date.distantPast
    var syncing = false

    /// hourly, and whenever a projects scan asks (it sets `projects.wanted` and waits for us)
    func maybeSyncProjects() {
        let wanted = ((state?["projects"] as? [String: Any])?["wanted"] as? Double).map { Date(timeIntervalSince1970: $0) } ?? .distantPast
        guard state != nil, projectsOn, !syncing, wanted > lastSync || Date().timeIntervalSince(lastSync) > 3600 else { return }
        syncing = true
        lastSync = Date()
        syncQueue.async {
            self.syncProjects()
            DispatchQueue.main.async { self.syncing = false }
        }
    }

    func syncProjects() {
        let fm = FileManager.default
        let root = projectsRoot
        do { _ = try fm.contentsOfDirectory(atPath: root.path) } catch {
            _ = call("/api/projects/sync", ["error": "the menu bar app can't read \(rootLabel) (\(error.localizedDescription)). Check the folder on the setup page, and allow pkgdash in System Settings → Privacy & Security → Files and Folders"])
            return
        }
        let keys: [URLResourceKey] = [.isDirectoryKey, .contentModificationDateKey, .fileSizeKey]
        let walker = fm.enumerator(at: root, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles, .skipsPackageDescendants])
        var manifest: [[String: Any]] = [], mtimes: [String: Double] = [:]
        while let u = walker?.nextObject() as? URL {
            let v = try? u.resourceValues(forKeys: Set(keys))
            if v?.isDirectory == true {
                if skipDirs.contains(u.lastPathComponent) || (walker?.level ?? 0) > 8 { walker?.skipDescendants() }
            } else if lockNames.contains(u.lastPathComponent), (v?.fileSize ?? 0) < 30_000_000 {
                let mt = v?.contentModificationDate?.timeIntervalSince1970 ?? 0
                manifest.append(["path": u.path, "mtime": mt])
                mtimes[u.path] = mt
            }
        }
        guard let r = call("/api/projects/sync", ["manifest": manifest]) else { return }
        for path in r["need"] as? [String] ?? [] {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            _ = call("/api/projects/sync", ["upload": ["path": path, "mtime": mtimes[path] ?? 0, "content": text]])
        }
        _ = call("/api/projects/sync", ["done": true])
    }

    // MARK: lockfile fixes (asked for from a project's row; run here because only this app can reach the projects folder)

    var startedFixes = Set<String>()

    /// Fixes are requested through the service, which any local program can talk to, so each one is
    /// shown here first and only runs once you allow it: this app holds the projects-folder permission.
    func runProjectFixes() {
        let tasks = (state?["projects"] as? [String: Any])?["tasks"] as? [[String: Any]] ?? []
        for t in tasks {
            guard let id = t["id"] as? String, !startedFixes.contains(id) else { continue }
            startedFixes.insert(id)
            let plan = fixPlan(t)
            guard case .success(let fix) = plan else {
                if case .failure(let why) = plan { syncQueue.async { _ = self.call("/api/projects/task", ["id": id, "rc": 2, "output": why.text]) } }
                continue
            }
            guard confirm(fix) else {
                syncQueue.async { _ = self.call("/api/projects/task", ["id": id, "rc": 1, "output": "declined in the menu bar app\n"]) }
                continue
            }
            syncQueue.async {
                let (rc, out) = self.runFix(fix)
                _ = self.call("/api/projects/task", ["id": id, "rc": Int(rc), "output": out])
                self.syncProjects()  // send the new lockfile straight away
            }
        }
    }

    struct Refusal: Error { let text: String }
    struct Fix { let cmd: [String]; let tool: String; let dir: URL; let files: [URL]; let project: String }

    /// Only these commands, and none of them install anything or run package code: they rewrite the lockfile.
    func fixPlan(_ t: [String: Any]) -> Result<Fix, Refusal> {
        let root = projectsRoot.path
        guard let path = t["path"] as? String, let kind = t["kind"] as? String else { return .failure(Refusal(text: "bad request\n")) }
        let lock = URL(fileURLWithPath: path).standardized
        guard projectsOn, lock.path.hasPrefix(root + "/"), lockNames.contains(lock.lastPathComponent) else {
            return .failure(Refusal(text: "refusing: \(path) isn't a lockfile in \(rootLabel)\n"))
        }
        let pkgs = (t["pkgs"] as? [String] ?? []).filter { $0.range(of: #"^[A-Za-z0-9@][A-Za-z0-9@/._-]*$"#, options: .regularExpression) != nil }
        let cmd: [String], manifest: String
        switch kind {
        case "npm": cmd = ["npm", "audit", "fix", "--package-lock-only", "--ignore-scripts", "--no-fund"]; manifest = "package.json"
        case "cargo": cmd = ["cargo", "update"] + pkgs; manifest = "Cargo.toml"
        case "uv": cmd = ["uv", "lock", "--no-build"] + pkgs.flatMap { ["--upgrade-package", $0] }; manifest = "pyproject.toml"
        default: return .failure(Refusal(text: "can't fix \(kind) lockfiles\n"))
        }
        if kind != "npm" && pkgs.isEmpty { return .failure(Refusal(text: "nothing to upgrade\n")) }
        guard let tool = which(cmd[0]) else { return .failure(Refusal(text: "\(cmd[0]) isn't installed\n")) }
        let dir = lock.deletingLastPathComponent()
        return .success(Fix(cmd: cmd, tool: tool, dir: dir, files: [lock, dir.appendingPathComponent(manifest)],
                            project: dir.path.replacingOccurrences(of: root + "/", with: "")))
    }

    func confirm(_ f: Fix) -> Bool {
        let a = NSAlert()
        a.messageText = "Fix the lockfile of \(f.project)?"
        a.informativeText = "pkgdash wants to run\n\n\(f.cmd.joined(separator: " "))\n\nin \(f.dir.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))\nusing \(f.tool)\n\nIt only rewrites the lockfile; nothing is installed. Allow it only if you just asked for this fix on the dashboard and you trust this project."
        a.addButton(withTitle: "Run Fix")
        a.addButton(withTitle: "Cancel")
        a.alertStyle = .warning
        NSApp.activate(ignoringOtherApps: true)
        return a.runModal() == .alertFirstButtonReturn
    }

    func runFix(_ f: Fix) -> (Int32, String) {
        // compared here rather than with `git diff`: git honours the repo's own config (core.fsmonitor,
        // diff.external…), which would let a cloned project run commands with this app's permissions
        let before = f.files.map { try? Data(contentsOf: $0) }
        var (rc, log) = run(f.tool, Array(f.cmd.dropFirst()), in: f.dir.path)
        log = "$ " + f.cmd.joined(separator: " ") + "   (" + f.tool + ")\n" + log + "\n# changed:\n"
        for (url, old) in zip(f.files, before) {
            let new = try? Data(contentsOf: url)
            guard old != nil || new != nil else { continue }
            log += "  \(url.lastPathComponent): " + (old == new ? "unchanged" : "\(changedLines(old, new)) lines changed") + "\n"
        }
        return (rc, log + "Review it with git diff in the repo.\n")
    }

    func changedLines(_ a: Data?, _ b: Data?) -> Int {
        var count: [Substring: Int] = [:]
        for l in String(decoding: a ?? Data(), as: UTF8.self).split(separator: "\n") { count[l, default: 0] += 1 }
        var added = 0
        for l in String(decoding: b ?? Data(), as: UTF8.self).split(separator: "\n") {
            if let c = count[l], c > 0 { count[l] = c - 1 } else { added += 1 }
        }
        return max(added, count.values.reduce(0, +))
    }

    let toolDirs: [String] = {
        let home = NSHomeDirectory()
        return ["\(home)/.local/bin", "\(home)/.local/share/fnm/aliases/default/bin", "/opt/homebrew/bin",
                "\(home)/.cargo/bin", "/usr/bin", "/bin"]
    }()

    func which(_ name: String) -> String? {
        toolDirs.map { $0 + "/" + name }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// Runs one of the lockfile tools by absolute path with a fresh environment: nothing from launchd's
    /// (user-editable) LaunchAgent, such as NODE_OPTIONS or DYLD_* variables, reaches it.
    func run(_ tool: String, _ args: [String], in dir: String) -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        p.currentDirectoryURL = URL(fileURLWithPath: dir)
        p.environment = [
            "HOME": NSHomeDirectory(), "USER": NSUserName(), "LOGNAME": NSUserName(), "TMPDIR": NSTemporaryDirectory(),
            "LANG": "en_US.UTF-8", "PATH": toolDirs.joined(separator: ":"), "NO_COLOR": "1",
            // the project's own config must not pick what runs or where packages come from: environment
            // beats .npmrc, .cargo/config.toml, rust-toolchain.toml and uv's python downloads
            "npm_config_ignore_scripts": "true", "npm_config_registry": "https://registry.npmjs.org/",
            "npm_config_git": "/usr/bin/git",
            "CARGO_BUILD_RUSTC": "rustc", "CARGO_BUILD_RUSTC_WRAPPER": "", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER": "",
            "CARGO_NET_GIT_FETCH_WITH_CLI": "false", "RUSTUP_TOOLCHAIN": "stable",
            "UV_PYTHON_DOWNLOADS": "never",
        ]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return (127, "can't run \(tool): \(error.localizedDescription)\n") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    /// blocking POST for the sync queue; refetches the token once if the service restarted
    func call(_ path: String, _ body: [String: Any]) -> [String: Any]? {
        for _ in 0..<2 {
            if token == nil {
                let sem = DispatchSemaphore(value: 0)
                fetchToken { t in self.token = t; sem.signal() }
                sem.wait()
            }
            guard let tok = token else { return nil }
            var req = URLRequest(url: URL(string: base + path)!)
            req.httpMethod = "POST"
            req.timeoutInterval = 120
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.setValue(tok, forHTTPHeaderField: "X-Pkgdash-Token")
            req.httpBody = try? JSONSerialization.data(withJSONObject: body)
            let sem = DispatchSemaphore(value: 0)
            var data: Data?, status = 0
            URLSession.shared.dataTask(with: req) { d, resp, _ in
                data = d
                status = (resp as? HTTPURLResponse)?.statusCode ?? 0
                sem.signal()
            }.resume()
            sem.wait()
            if status == 403 { token = nil; continue }
            return data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        }
        return nil
    }

    func redraw() {
        guard state != nil else { return setIcon("exclamationmark.triangle", "off") }
        let high = totals["high"] ?? 0
        if !activeJobs.isEmpty {
            setIcon("arrow.triangle.2.circlepath", high > 0 ? "\(high)" : "")
        } else {
            setIcon(high > 0 ? "shippingbox.fill" : "shippingbox", high > 0 ? "\(high)" : "")
        }
        item.button?.toolTip = state == nil ? "pkgdash offline" :
            "pkgdash — \(totals["packages"] ?? 0) packages · \(totals["vulns"] ?? 0) vulns (\(high) high/critical) · \(totals["outdated"] ?? 0) outdated"
    }

    // MARK: clicks & menu

    @objc func clicked() {
        let e = NSApp.currentEvent
        if e?.type == .rightMouseUp || e?.modifierFlags.contains(.control) == true || e?.modifierFlags.contains(.option) == true {
            item.menu = buildMenu()
            item.button?.performClick(nil)
            item.menu = nil
        } else {
            open("dashboard")
        }
    }

    func buildMenu() -> NSMenu {
        let m = NSMenu()
        func info(_ t: String) { let i = NSMenuItem(title: t, action: nil, keyEquivalent: ""); i.isEnabled = false; m.addItem(i) }
        func act(_ t: String, _ key: String, _ rep: String, _ sel: Selector, to menu: NSMenu? = nil) {
            let i = NSMenuItem(title: t, action: sel, keyEquivalent: key)
            i.target = self
            i.representedObject = rep
            (menu ?? m).addItem(i)
        }
        if state == nil {
            info("pkgdash — OFFLINE (service not responding)")
        } else {
            let t = totals
            info("pkgdash — ONLINE")
            info("\(t["packages"] ?? 0) packages · \(t["outdated"] ?? 0) outdated")
            info("\(t["vulns"] ?? 0) vulns · \(t["high"] ?? 0) high/critical")
            let running = activeJobs.map { "\($0["manager"] ?? "") \($0["action"] ?? "")" }
            if !running.isEmpty { info("● running: " + running.joined(separator: ", ")) }
            if let u = state?["unread"] as? Int, u > 0 { act("✉︎ \(u) unread event\(u == 1 ? "" : "s")…", "", "events", #selector(openRoute(_:))) }
        }
        m.addItem(.separator())
        act("Open Dashboard", "o", "dashboard", #selector(openRoute(_:)))
        act("Vulnerabilities", "v", "vulns", #selector(openRoute(_:)))
        m.addItem(.separator())
        act("Scan All", "s", "all:scan", #selector(runAction(_:)))
        act("Audit All", "a", "all:audit", #selector(runAction(_:)))
        if !managers.isEmpty {
            m.addItem(.separator())
            for mg in managers {
                let id = mg["id"] as? String ?? "?"
                let vulns = mg["vulns"] as? Int ?? 0, count = mg["count"] as? Int ?? 0, outd = mg["outdated"] as? Int ?? 0
                var title = "\(id) — \(count) pkgs"
                if vulns > 0 { title += " · \(vulns) vulns" }
                if outd > 0 { title += " · \(outd) outdated" }
                if !((mg["busy"] as? [String]) ?? []).isEmpty { title += "  ●" }
                let sub = NSMenu()
                act("Open", "", "m/" + id, #selector(openRoute(_:)), to: sub)
                for a in (mg["actions"] as? [String] ?? []) where a != "update" {
                    act(a.capitalized, "", "\(id):\(a)", #selector(runAction(_:)), to: sub)
                }
                let it = NSMenuItem(title: title, action: nil, keyEquivalent: "")
                it.submenu = sub
                m.addItem(it)
            }
        }
        m.addItem(.separator())
        let q = NSMenuItem(title: "Quit Menu Icon", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        m.addItem(q)
        return m
    }

    @objc func openRoute(_ s: NSMenuItem) { open(s.representedObject as? String ?? "dashboard") }

    func open(_ route: String) {
        NSWorkspace.shared.open(URL(string: "\(base)/#/\(route)")!)
    }

    // MARK: actions (POSTs need the per-process token embedded in the page)

    @objc func runAction(_ s: NSMenuItem) {
        let parts = (s.representedObject as? String ?? "").split(separator: ":").map(String.init)
        guard parts.count == 2 else { return }
        post(manager: parts[0], action: parts[1], retry: true)
    }

    func fetchToken(_ done: @escaping (String?) -> Void) {
        URLSession.shared.dataTask(with: URL(string: base + "/")!) { data, _, _ in
            let html = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let r = html.range(of: #"TOKEN = "([^"]+)""#, options: .regularExpression)
            let tok = r.map { String(html[$0]).components(separatedBy: "\"")[1] }
            DispatchQueue.main.async { done(tok) }
        }.resume()
    }

    func post(manager: String, action: String, retry: Bool) {
        guard let tok = token else {
            return fetchToken { t in
                guard let t = t else { return }
                self.token = t
                self.post(manager: manager, action: action, retry: false)
            }
        }
        var req = URLRequest(url: URL(string: base + "/api/run")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(tok, forHTTPHeaderField: "X-Pkgdash-Token")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["manager": manager, "action": action])
        URLSession.shared.dataTask(with: req) { _, resp, _ in
            DispatchQueue.main.async {
                if (resp as? HTTPURLResponse)?.statusCode == 403 && retry {  // service restarted → new token
                    self.token = nil
                    self.post(manager: manager, action: action, retry: false)
                } else {
                    self.refresh()
                }
            }
        }.resume()
    }
}

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
