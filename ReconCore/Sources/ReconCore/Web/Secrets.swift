import Foundation

/// Scans text (source files, JS bundles, config dumps, HTTP responses) for leaked credentials,
/// API keys and private keys — the kind of thing left in client-side code or exposed configs.
public enum SecretScanner {
    struct Rule { let name: String; let pattern: String; let severity: Severity }

    static let rules: [Rule] = [
        Rule(name: "AWS Access Key ID", pattern: #"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"#, severity: .critical),
        Rule(name: "AWS Secret Access Key", pattern: #"(?i)aws(.{0,20})?(secret|private)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"#, severity: .critical),
        Rule(name: "GitHub Token", pattern: #"\bgh[pousr]_[0-9A-Za-z]{36,251}\b"#, severity: .critical),
        Rule(name: "GitHub Fine-grained PAT", pattern: #"\bgithub_pat_[0-9A-Za-z_]{82}\b"#, severity: .critical),
        Rule(name: "GitLab PAT", pattern: #"\bglpat-[0-9A-Za-z\-_]{20}\b"#, severity: .critical),
        Rule(name: "Slack Token", pattern: #"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"#, severity: .high),
        Rule(name: "Slack Webhook", pattern: #"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"#, severity: .high),
        Rule(name: "Google API Key", pattern: #"\bAIza[0-9A-Za-z\-_]{35}\b"#, severity: .high),
        Rule(name: "Google OAuth Client", pattern: #"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"#, severity: .medium),
        Rule(name: "Stripe Live Secret Key", pattern: #"\bsk_live_[0-9A-Za-z]{24,}\b"#, severity: .critical),
        Rule(name: "Stripe Test Secret Key", pattern: #"\bsk_test_[0-9A-Za-z]{24,}\b"#, severity: .medium),
        Rule(name: "Stripe Restricted Key", pattern: #"\brk_live_[0-9A-Za-z]{24,}\b"#, severity: .high),
        Rule(name: "Twilio API Key", pattern: #"\bSK[0-9a-fA-F]{32}\b"#, severity: .high),
        Rule(name: "SendGrid API Key", pattern: #"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"#, severity: .high),
        Rule(name: "Mailgun Key", pattern: #"\bkey-[0-9a-f]{32}\b"#, severity: .high),
        Rule(name: "Square Access Token", pattern: #"\b(sq0atp|sq0csp|EAAA)[0-9A-Za-z\-_]{22,}\b"#, severity: .high),
        Rule(name: "npm Token", pattern: #"\bnpm_[0-9A-Za-z]{36}\b"#, severity: .high),
        Rule(name: "OpenAI API Key", pattern: #"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"#, severity: .high),
        Rule(name: "Heroku API Key", pattern: #"(?i)heroku(.{0,15})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"#, severity: .high),
        Rule(name: "Private Key Block", pattern: #"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"#, severity: .critical),
        Rule(name: "JSON Web Token", pattern: #"\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"#, severity: .medium),
        Rule(name: "Basic Auth in URL", pattern: #"(?i)[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@"#, severity: .high),
        Rule(name: "Generic Secret Assignment", pattern: #"(?i)(api[_-]?key|secret|token|passwd|password|auth[_-]?token|access[_-]?key)['\"]?\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"#, severity: .medium)
    ]

    /// Shannon entropy in bits per character.
    public static func entropy(_ s: String) -> Double {
        guard !s.isEmpty else { return 0 }
        var counts: [Character: Int] = [:]
        for c in s { counts[c, default: 0] += 1 }
        let n = Double(s.count)
        return counts.values.reduce(0.0) { acc, c in
            let p = Double(c) / n
            return acc - p * log2(p)
        }
    }

    static func mask(_ s: String) -> String {
        guard s.count > 12 else { return s }
        return "\(s.prefix(6))…\(s.suffix(4))  (\(s.count) chars)"
    }

    public static func scan(_ text: String) -> [Finding] {
        var findings: [Finding] = []
        var seen = Set<String>()
        let ns = text as NSString
        for rule in rules {
            guard let re = try? NSRegularExpression(pattern: rule.pattern) else { continue }
            for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                let hit = ns.substring(with: m.range)
                let dedupeKey = rule.name + "|" + hit
                guard seen.insert(dedupeKey).inserted else { continue }
                findings.append(Finding(rule.severity, "\(rule.name)", mask(hit.trimmed()), source: "secrets"))
            }
        }
        // Generic high-entropy tokens that no rule caught.
        if let re = try? NSRegularExpression(pattern: #"[A-Za-z0-9+/_\-]{24,}"#) {
            for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                let tok = ns.substring(with: m.range)
                let e = entropy(tok)
                if e >= 4.0, seen.insert("entropy|" + tok).inserted, findings.count < 60 {
                    findings.append(Finding(.low, "High-entropy string", "\(mask(tok))  entropy \(String(format: "%.1f", e)) bits/char", source: "secrets"))
                }
            }
        }
        return findings
    }

    public static func run(_ input: String) -> ToolOutput {
        var out = ToolOutput()
        let findings = scan(input)
        out.findings = findings.filter { $0.severity >= .medium }
        var s = ReportSection("Secret & credential scan",
                              note: "Matched \(rules.count) credential formats plus a Shannon-entropy sweep. Values are masked.")
        if findings.isEmpty {
            s.add("Result", "no secrets detected in \(input.count) chars", .info)
        } else {
            for f in findings.sorted(by: { $0.severity > $1.severity }) {
                s.add(f.title, f.detail, f.severity)
            }
        }
        out.sections = [s]
        return out
    }

    /// Convenience for the recon pipeline: pull JS URLs from HTML and scan their bodies.
    public static func scanWeb(_ url: URL) async -> ToolOutput {
        guard let probe = try? await WebRecon.fetch(url) else { return ToolOutput() }
        let html = probe.final.text
        var bodies = [html]
        // Find same-origin script srcs.
        if let re = try? NSRegularExpression(pattern: #"<script[^>]+src=[\"']([^\"']+\.js[^\"']*)[\"']"#, options: [.caseInsensitive]) {
            let ns = html as NSString
            var urls: [URL] = []
            for m in re.matches(in: html, range: NSRange(location: 0, length: ns.length)).prefix(12) {
                if let u = URL(string: ns.substring(with: m.range(at: 1)), relativeTo: probe.finalURL)?.absoluteURL { urls.append(u) }
            }
            let fetched = await boundedMap(urls, limit: 6) { (try? await HTTP.request($0, timeout: 10, maxBytes: 2_000_000))?.text ?? "" }
            bodies += fetched
        }
        var out = ToolOutput()
        let findings = scan(bodies.joined(separator: "\n"))
        out.findings = findings.filter { $0.severity >= .medium }
        if !findings.isEmpty {
            var s = ReportSection("Secrets in web assets (\(url.host ?? ""))")
            for f in findings.sorted(by: { $0.severity > $1.severity }).prefix(40) { s.add(f.title, f.detail, f.severity) }
            out.sections = [s]
        }
        return out
    }
}
