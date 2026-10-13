import Foundation

/// CVSS v3.1 base-score calculator. Parses a vector string and computes the score + severity.
public enum CVSS {
    static let av: [String: Double] = ["N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2]
    static let ac: [String: Double] = ["L": 0.77, "H": 0.44]
    static let ui: [String: Double] = ["N": 0.85, "R": 0.62]
    static let cia: [String: Double] = ["H": 0.56, "L": 0.22, "N": 0.0]

    public static func severity(_ score: Double) -> Severity {
        switch score {
        case 0: return .info
        case ..<4.0: return .low
        case ..<7.0: return .medium
        case ..<9.0: return .high
        default: return .critical
        }
    }

    static func roundUp(_ x: Double) -> Double {
        // CVSS 3.1 Roundup: ceil to one decimal with integer-math to avoid float drift.
        let i = Int((x * 100000).rounded())
        if i % 10000 == 0 { return Double(i) / 100000.0 }
        return (Double(i / 10000) + 1) / 10.0
    }

    public struct Result { public let score: Double; public let severity: Severity; public let metrics: [String: String] }

    public static func score(vector: String) -> Result? {
        var m: [String: String] = [:]
        for part in vector.uppercased().split(separator: "/") {
            let kv = part.split(separator: ":")
            if kv.count == 2 { m[String(kv[0])] = String(kv[1]) }
        }
        guard let avV = av[m["AV"] ?? ""], let acV = ac[m["AC"] ?? ""], let uiV = ui[m["UI"] ?? ""],
              let c = cia[m["C"] ?? ""], let i = cia[m["I"] ?? ""], let a = cia[m["A"] ?? ""],
              let prRaw = m["PR"], let scope = m["S"], scope == "U" || scope == "C" else { return nil }

        let changed = scope == "C"
        let pr: Double
        switch prRaw {
        case "N": pr = 0.85
        case "L": pr = changed ? 0.68 : 0.62
        case "H": pr = changed ? 0.50 : 0.27
        default: return nil
        }

        let iss = 1 - (1 - c) * (1 - i) * (1 - a)
        let impact = changed ? 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15) : 6.42 * iss
        let exploitability = 8.22 * avV * acV * pr * uiV
        var base = 0.0
        if impact > 0 {
            base = changed ? roundUp(min(1.08 * (impact + exploitability), 10))
                           : roundUp(min(impact + exploitability, 10))
        }
        return Result(score: base, severity: severity(base), metrics: m)
    }

    static let labels: [String: [String: String]] = [
        "AV": ["N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"],
        "AC": ["L": "Low", "H": "High"],
        "PR": ["N": "None", "L": "Low", "H": "High"],
        "UI": ["N": "None", "R": "Required"],
        "S": ["U": "Unchanged", "C": "Changed"],
        "C": ["H": "High", "L": "Low", "N": "None"],
        "I": ["H": "High", "L": "Low", "N": "None"],
        "A": ["H": "High", "L": "Low", "N": "None"]
    ]
    static let names: [String: String] = ["AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required",
                                          "UI": "User Interaction", "S": "Scope", "C": "Confidentiality", "I": "Integrity", "A": "Availability"]

    public static func run(_ input: String) -> ToolOutput {
        var v = input.trimmed()
        if let r = v.range(of: "CVSS:3.", options: .caseInsensitive) {
            // drop the "CVSS:3.1/" prefix if present
            if let slash = v[r.lowerBound...].firstIndex(of: "/") { v = String(v[v.index(after: slash)...]) }
        }
        guard let result = score(vector: v) else {
            return ToolOutput(sections: [ReportSection("CVSS v3.1", items: [
                ReportItem("Usage", "paste a vector, e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", .low)])])
        }
        var out = ToolOutput()
        var s = ReportSection("CVSS v3.1 base score")
        s.add("Score", String(format: "%.1f", result.score), result.severity)
        s.add("Severity", result.severity.rawValue.capitalized, result.severity)
        for key in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] {
            if let val = result.metrics[key] { s.add(names[key] ?? key, labels[key]?[val] ?? val) }
        }
        out.sections = [s]
        if result.severity >= .high { out.findings.append(Finding(result.severity, "CVSS \(String(format: "%.1f", result.score)) (\(result.severity.rawValue))", v, source: "cvss")) }
        return out
    }
}
