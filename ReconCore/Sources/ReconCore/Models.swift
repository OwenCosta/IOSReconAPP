import Foundation

// MARK: - Errors

public enum ReconError: Error, LocalizedError, Sendable {
    case invalidInput(String)
    case network(String)
    case http(Int)
    case parse(String)
    case unsupported(String)

    public var errorDescription: String? {
        switch self {
        case .invalidInput(let m): return "Invalid input: \(m)"
        case .network(let m): return "Network error: \(m)"
        case .http(let c): return "HTTP error \(c)"
        case .parse(let m): return "Could not parse response: \(m)"
        case .unsupported(let m): return m
        }
    }
}

// MARK: - Report model (shared by every tool, rendered generically by the UI)

public enum Severity: String, Codable, CaseIterable, Comparable, Sendable {
    case info, low, medium, high, critical

    private var rank: Int { Severity.allCases.firstIndex(of: self) ?? 0 }
    public static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }
}

public struct ReportItem: Codable, Identifiable, Hashable, Sendable {
    public var id = UUID()
    public var label: String
    public var value: String
    public var severity: Severity

    public init(_ label: String, _ value: String, _ severity: Severity = .info) {
        self.label = label
        self.value = value
        self.severity = severity
    }
}

public struct ReportSection: Codable, Identifiable, Hashable, Sendable {
    public var id = UUID()
    public var title: String
    public var items: [ReportItem]
    public var note: String?

    public init(_ title: String, items: [ReportItem] = [], note: String? = nil) {
        self.title = title
        self.items = items
        self.note = note
    }

    public mutating func add(_ label: String, _ value: String, _ severity: Severity = .info) {
        items.append(ReportItem(label, value, severity))
    }
}

public struct Finding: Codable, Identifiable, Hashable, Sendable {
    public var id = UUID()
    public var severity: Severity
    public var title: String
    public var detail: String
    public var source: String

    public init(_ severity: Severity, _ title: String, _ detail: String = "", source: String = "") {
        self.severity = severity
        self.title = title
        self.detail = detail
        self.source = source
    }
}

/// What every tool returns: human readable sections plus machine-ranked findings.
public struct ToolOutput: Sendable {
    public var sections: [ReportSection]
    public var findings: [Finding]

    public init(sections: [ReportSection] = [], findings: [Finding] = []) {
        self.sections = sections
        self.findings = findings
    }

    public mutating func merge(_ other: ToolOutput) {
        sections += other.sections
        findings += other.findings
    }

    /// A plain-text rendering for feeding a tool's result back to an LLM (or logging it) —
    /// compact, bounded in size, no UI concepts. Pure and deterministic.
    public func renderCompact(maxChars: Int = 6000) -> String {
        var lines: [String] = []
        for s in sections {
            lines.append("## \(s.title)")
            if let n = s.note, !n.isEmpty { lines.append("(\(n))") }
            for item in s.items {
                lines.append(item.label.isEmpty ? item.value : "\(item.label): \(item.value)")
            }
        }
        if !findings.isEmpty {
            lines.append("## Findings")
            for f in findings {
                lines.append("[\(f.severity.rawValue)] \(f.title)" + (f.detail.isEmpty ? "" : " — \(f.detail)"))
            }
        }
        if lines.isEmpty { return "(no output)" }
        let text = lines.joined(separator: "\n")
        guard text.count > maxChars else { return text }
        let cut = text.index(text.startIndex, offsetBy: maxChars)
        return String(text[..<cut]) + "\n… (truncated)"
    }
}

public struct ReconReport: Codable, Identifiable, Sendable {
    public var id = UUID()
    public var kind: String
    public var target: String
    public var started: Date
    public var finished: Date?
    public var sections: [ReportSection]
    public var findings: [Finding]
    /// Folder/engagement this report belongs to. Optional so older saved reports still decode.
    public var project: String?

    public init(kind: String, target: String, started: Date = Date(), finished: Date? = nil,
                sections: [ReportSection] = [], findings: [Finding] = [], project: String? = nil) {
        self.kind = kind
        self.target = target
        self.started = started
        self.finished = finished
        self.sections = sections
        self.findings = findings
        self.project = project
    }

    public var worstSeverity: Severity { findings.map(\.severity).max() ?? .info }
}

// MARK: - Tool context

/// Lets the host app hand API keys to the core library without the core knowing about Keychain.
public protocol SecretsProvider: Sendable {
    func secret(_ name: String) -> String?
}

public struct NoSecrets: SecretsProvider {
    public init() {}
    public func secret(_ name: String) -> String? { nil }
}

public struct ToolContext: Sendable {
    public var secrets: SecretsProvider
    public var log: @Sendable (String) -> Void

    public init(secrets: SecretsProvider = NoSecrets(), log: @escaping @Sendable (String) -> Void = { _ in }) {
        self.secrets = secrets
        self.log = log
    }

    public static let silent = ToolContext()
}

// MARK: - Small helpers

extension StringProtocol {
    func trimmed() -> String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

extension Array {
    func chunked(into size: Int) -> [[Element]] {
        guard size > 0 else { return [self] }
        return stride(from: 0, to: count, by: size).map { Array(self[$0..<Swift.min($0 + size, count)]) }
    }
}

/// Run `work` over `inputs` with at most `limit` in flight, preserving nothing about order.
func boundedMap<I: Sendable, O: Sendable>(_ inputs: [I], limit: Int,
                                          _ work: @escaping @Sendable (I) async -> O) async -> [O] {
    var results: [O] = []
    results.reserveCapacity(inputs.count)
    await withTaskGroup(of: O.self) { group in
        var idx = 0
        while idx < min(limit, inputs.count) {
            let item = inputs[idx]; idx += 1
            group.addTask { await work(item) }
        }
        while let r = await group.next() {
            results.append(r)
            if idx < inputs.count && !Task.isCancelled {
                let item = inputs[idx]; idx += 1
                group.addTask { await work(item) }
            }
        }
    }
    return results
}
