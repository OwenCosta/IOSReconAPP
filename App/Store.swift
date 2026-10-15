import SwiftUI
import Security
import ReconCore

// MARK: - Saved reports

@MainActor
final class SessionStore: ObservableObject {
    @Published private(set) var reports: [ReconReport] = []
    /// Folders the user created explicitly (may be empty, i.e. hold no reports yet).
    @Published private(set) var createdFolders: [String] = []
    /// Folder names the user has collapsed in the Reports list.
    @Published private(set) var collapsed: Set<String> = []

    private let url: URL = {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("reports.json")
    }()

    private let metaURL: URL = {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("folders.json")
    }()

    init() { load() }

    func add(_ report: ReconReport) {
        reports.insert(report, at: 0)
        if reports.count > 200 { reports.removeLast(reports.count - 200) }
        save()
    }

    func delete(at offsets: IndexSet) {
        reports.remove(atOffsets: offsets)
        save()
    }

    func delete(_ report: ReconReport) {
        reports.removeAll { $0.id == report.id }
        save()
    }

    /// Rename a report's displayed target (e.g. to fix a generic/mistyped name — a hidden-input
    /// tool's "(hidden input)" placeholder is a common case). No-ops on an empty name — callers
    /// must check the return value before updating their own local copy of the report, or their
    /// view ends up showing a new title that was never actually saved.
    @discardableResult
    func rename(_ report: ReconReport, to newTarget: String) -> Bool {
        let t = newTarget.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, let i = reports.firstIndex(where: { $0.id == report.id }) else { return false }
        reports[i].target = t
        save()
        return true
    }

    func clear() {
        reports.removeAll()
        save()
    }

    // MARK: Folders / projects

    static let unsorted = "Unsorted"

    func folder(of report: ReconReport) -> String {
        let p = report.project?.trimmingCharacters(in: .whitespaces) ?? ""
        return p.isEmpty ? Self.unsorted : p
    }

    /// Folder names, most-recently-updated first, including empty user-created folders.
    var folders: [String] {
        var seen = [String: Date]()
        for r in reports {
            let f = folder(of: r)
            let t = r.finished ?? r.started
            if let existing = seen[f] { if t > existing { seen[f] = t } } else { seen[f] = t }
        }
        var order = seen.sorted { $0.value > $1.value }.map(\.key)
        // Empty created folders (no reports yet) sort to the top, newest-created first.
        for f in createdFolders.reversed() where seen[f] == nil && f != Self.unsorted {
            order.insert(f, at: 0)
        }
        return order
    }

    func reports(in folder: String) -> [ReconReport] {
        reports.filter { self.folder(of: $0) == folder }.sorted { ($0.finished ?? $0.started) > ($1.finished ?? $1.started) }
    }

    /// Create a named folder up front (before any report is moved into it).
    @discardableResult
    func createFolder(_ name: String) -> String? {
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty, n != Self.unsorted else { return nil }
        if !folders.contains(n) { createdFolders.append(n) }
        collapsed.remove(n)
        saveMeta()
        return n
    }

    func isCollapsed(_ folder: String) -> Bool { collapsed.contains(folder) }

    func toggleCollapse(_ folder: String) {
        if collapsed.contains(folder) { collapsed.remove(folder) } else { collapsed.insert(folder) }
        saveMeta()
    }

    func move(_ report: ReconReport, to folder: String?) {
        guard let i = reports.firstIndex(where: { $0.id == report.id }) else { return }
        let f = folder?.trimmingCharacters(in: .whitespaces)
        let dest: String? = (f == nil || f!.isEmpty || f == Self.unsorted) ? nil : f
        reports[i].project = dest
        // Once a report lives in a folder it is no longer merely "created & empty".
        if let d = dest { createdFolders.removeAll { $0 == d } }
        save()
        saveMeta()
    }

    func renameFolder(_ old: String, to new: String) {
        let newName = new.trimmingCharacters(in: .whitespaces)
        guard !newName.isEmpty, newName != old else { return }
        let target: String? = (newName == Self.unsorted) ? nil : newName
        for i in reports.indices where folder(of: reports[i]) == old {
            reports[i].project = target
        }
        // Carry an empty created folder + its collapse state across the rename.
        if let idx = createdFolders.firstIndex(of: old) {
            if let t = target, !createdFolders.contains(t) { createdFolders[idx] = t } else { createdFolders.remove(at: idx) }
        }
        if collapsed.remove(old) != nil, let t = target { collapsed.insert(t) }
        save()
        saveMeta()
    }

    func deleteFolder(_ name: String) {
        reports.removeAll { folder(of: $0) == name }
        createdFolders.removeAll { $0 == name }
        collapsed.remove(name)
        save()
        saveMeta()
    }

    private func load() {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        if let data = try? Data(contentsOf: url) {
            if let decoded = try? dec.decode([ReconReport].self, from: data) {
                reports = decoded
            } else if let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                // The whole-array decode failed — one malformed or legacy report is enough to
                // break it for every report in the file. Falling back to decoding element by
                // element means a single bad entry just gets skipped instead of silently
                // wiping every other saved report (and the next save() permanently losing
                // them, since save() overwrites this same file).
                reports = array.compactMap { obj in
                    guard let itemData = try? JSONSerialization.data(withJSONObject: obj) else { return nil }
                    return try? dec.decode(ReconReport.self, from: itemData)
                }
            }
        }
        if let data = try? Data(contentsOf: metaURL), let meta = try? dec.decode(FolderMeta.self, from: data) {
            createdFolders = meta.created
            collapsed = Set(meta.collapsed)
        }
    }

    private func save() {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        if let data = try? enc.encode(reports) {
            try? data.write(to: url, options: [.atomic, .completeFileProtection])
        }
    }

    private func saveMeta() {
        let enc = JSONEncoder()
        let meta = FolderMeta(created: createdFolders, collapsed: Array(collapsed))
        if let data = try? enc.encode(meta) {
            try? data.write(to: metaURL, options: [.atomic, .completeFileProtection])
        }
    }

    private struct FolderMeta: Codable { var created: [String]; var collapsed: [String] }
}

// MARK: - API keys in the Keychain

struct KeychainSecrets: SecretsProvider {
    static let service = "com.reconkit.apikeys"

    func secret(_ name: String) -> String? { Self.get(name) }

    static func get(_ name: String) -> String? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        let value = String(data: data, encoding: .utf8)
        return (value?.isEmpty ?? true) ? nil : value
    }

    static func set(_ value: String, for name: String) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name
        ]
        SecItemDelete(base as CFDictionary)
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var add = base
        add[kSecValueData as String] = Data(trimmed.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }
}

// MARK: - Generic tool runner

@MainActor
final class ToolRunnerModel: ObservableObject {
    @Published var running = false
    @Published var output: ToolOutput?
    @Published var error: String?
    @Published var log: [String] = []
    private var task: Task<Void, Never>?

    func run(_ spec: ToolSpec, input: String) {
        cancel()
        running = true
        output = nil
        error = nil
        log = []
        let secrets = KeychainSecrets()
        task = Task { [weak self] in
            let ctx = ToolContext(secrets: secrets, log: { line in
                Task { @MainActor in self?.append(line) }
            })
            do {
                let result = try await spec.run(input, ctx)
                if !Task.isCancelled { self?.output = result }
            } catch {
                if !Task.isCancelled { self?.error = error.localizedDescription }
            }
            self?.running = false
        }
    }

    func cancel() {
        task?.cancel()
        task = nil
        running = false
    }

    private func append(_ line: String) {
        log.append(line)
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }
}

// MARK: - Helpers

func scanReport(target: String, hosts: [HostResult]) -> ReconReport {
    // Group a scan under a folder named after its target (first host if it's a range/CIDR).
    let folder = hosts.count == 1 ? hosts[0].host : TargetParser.stripToHost(target)
    var report = ReconReport(kind: "Port Scan", target: target, finished: Date(),
                             project: folder.isEmpty ? nil : folder)
    for h in hosts {
        var s = ReportSection("Host \(h.host)", note: "Found via \(h.aliveReason). \(h.closedCount) closed, \(h.filteredCount) filtered.")
        for p in h.openPorts {
            let risk = p.proto == "tcp" ? ServiceDB.risk(port: p.port) : nil
            var v = p.service
            if let ver = p.version { v += "  \(ver)" } else if let b = p.banner { v += "  “\(b.prefix(100))”" }
            s.add("\(p.port)/\(p.proto)", v, risk?.severity ?? .info)
            if let r = risk, r.severity >= .medium {
                report.findings.append(Finding(r.severity, "Open \(p.service) (\(p.port)) on \(h.host)", r.why, source: "portscan"))
            }
        }
        if h.openPorts.isEmpty { s.add("Result", "no open ports found") }
        if h.likelyProxyInterference {
            s.add("⚠︎ Warning", "\(h.openPorts.count)/\(h.scannedCount) ports look open. A carrier NAT, captive portal or proxy is probably answering for every port. These results are unreliable; re-scan on Wi-Fi.", .high)
            report.findings.append(Finding(.medium, "Scan of \(h.host) may be unreliable (proxy/NAT interference)", "Almost all probed ports reported open.", source: "portscan"))
        }
        if let hint = h.deviceHint, !h.likelyProxyInterference { s.add("Role hint", hint) }
        report.sections.append(s)
    }
    return report
}
