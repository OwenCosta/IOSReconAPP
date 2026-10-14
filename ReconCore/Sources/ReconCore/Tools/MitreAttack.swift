import Foundation

/// A complete, offline MITRE ATT&CK (Enterprise) knowledge base: all 15 current tactics
/// and all 227 top-level techniques (sub-techniques, e.g. T1556.006, are out of scope),
/// each with MITRE's own description plus general detection/mitigation guidance for its
/// tactic. The data itself lives in Resources/mitre_attack.json (not as a huge Swift
/// literal) — a single giant array-literal source file is slow for Xcode's editor/SourceKit
/// to index and a pain to diff, where a bundled JSON resource decoded once at first use
/// has neither problem. Generated from the live attack.mitre.org Enterprise matrix. For
/// planning and understanding adversary behaviour on authorised engagements / CTFs — a
/// reference to actually learn from, not a cherry-picked sample.
public enum MitreAttack {
    public struct Technique: Identifiable, Sendable, Decodable {
        public let id: String            // e.g. T1059
        public let name: String
        public let tactics: [String]     // tactic ids this technique belongs to, e.g. [TA0002]
        public let summary: String
        public let detection: String
        public let mitigation: String

        private enum CodingKeys: String, CodingKey {
            case id, name, tactics, summary
            case detection = "detect"
            case mitigation = "mitigate"
        }
    }

    public struct Tactic: Identifiable, Sendable, Decodable {
        public let id: String            // e.g. TA0001
        public let name: String
        public let summary: String
    }

    private struct Database: Decodable {
        let tactics: [Tactic]
        let techniques: [Technique]
    }

    private static let database: Database = {
        guard let url = Bundle.module.url(forResource: "mitre_attack", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let db = try? JSONDecoder().decode(Database.self, from: data) else {
            assertionFailure("MitreAttack: failed to load mitre_attack.json from the ReconCore bundle")
            return Database(tactics: [], techniques: [])
        }
        return db
    }()

    public static var tactics: [Tactic] { database.tactics }
    public static var techniques: [Technique] { database.techniques }

    public static func tactic(_ id: String) -> Tactic? { tactics.first { $0.id.caseInsensitiveCompare(id) == .orderedSame } }
    public static func technique(_ id: String) -> Technique? { techniques.first { $0.id.caseInsensitiveCompare(id) == .orderedSame } }
    public static func techniques(in tacticID: String) -> [Technique] {
        techniques.filter { t in t.tactics.contains { $0.caseInsensitiveCompare(tacticID) == .orderedSame } }
    }

    public static func search(_ query: String) -> [Technique] {
        let q = query.lowercased()
        return techniques.filter { $0.name.lowercased().contains(q) || $0.summary.lowercased().contains(q)
            || $0.detection.lowercased().contains(q) || $0.mitigation.lowercased().contains(q) || $0.id.lowercased().contains(q) }
    }

    public static func run(_ input: String) -> ToolOutput {
        let q = input.trimmed()
        // Technique id → detail
        if let t = technique(q) { return detail(t) }
        // Tactic id → techniques in it
        if let ta = tactic(q) {
            var s = ReportSection("\(ta.id) — \(ta.name)", note: ta.summary)
            for t in techniques(in: ta.id) { s.add(t.id, t.name) }
            return ToolOutput(sections: [s])
        }
        // Keyword search
        if !q.isEmpty {
            let hits = search(q)
            if hits.isEmpty {
                return ToolOutput(sections: [ReportSection("ATT&CK", items: [ReportItem("No match", "try a tactic (TA0002), a technique (T1059) or a keyword (phishing, brute, exfil)", .low)])])
            }
            var out = ToolOutput()
            var s = ReportSection("Matches for \u{201c}\(q)\u{201d} (\(hits.count))")
            for t in hits.prefix(60) { s.add(t.id, "\(t.name) — \(t.tactics.compactMap { tactic($0)?.name }.joined(separator: ", "))") }
            out.sections.append(s)
            return out
        }
        // Empty → the matrix overview
        var out = ToolOutput()
        var s = ReportSection("MITRE ATT&CK — Enterprise tactics", note: "Enter a tactic id (TA0001), technique id (T1059) or keyword. \(techniques.count) techniques covered.")
        for ta in tactics { s.add("\(ta.id) · \(ta.name)", "\(techniques(in: ta.id).count) techniques") }
        out.sections.append(s)
        return out
    }

    static func detail(_ t: Technique) -> ToolOutput {
        let tacticNames = t.tactics.compactMap { tactic($0)?.name }.joined(separator: ", ")
        var s = ReportSection("\(t.id) — \(t.name)", note: "Tactic: \(tacticNames)")
        s.add("What", t.summary)
        s.add("Detect", t.detection, .low)
        s.add("Mitigate", t.mitigation, .low)
        s.add("Reference", "https://attack.mitre.org/techniques/\(t.id.replacingOccurrences(of: ".", with: "/"))/")
        return ToolOutput(sections: [s])
    }
}
