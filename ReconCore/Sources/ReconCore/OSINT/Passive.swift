import Foundation

// MARK: - Certificate Transparency

public enum CertTransparency {
    /// Subdomains seen in public CT logs. crt.sh first, Cert Spotter as fallback.
    public static func subdomains(of domain: String, ctx: ToolContext = .silent) async throws -> [String] {
        var names = Set<String>()
        var crtError: Error?
        do {
            let url = try HTTP.url("https://crt.sh/?q=%25.\(HTTP.q(domain))&output=json")
            let raw = try await HTTP.json(url, timeout: 45, maxBytes: 25_000_000)
            for row in (raw as? [[String: Any]]) ?? [] {
                for n in (row.str("name_value") ?? "").split(separator: "\n") { names.insert(clean(String(n))) }
            }
        } catch {
            crtError = error
            ctx.log("crt.sh failed (\(error.localizedDescription)); trying Cert Spotter…")
        }
        if names.isEmpty {
            let url = try HTTP.url("https://api.certspotter.com/v1/issuances?domain=\(HTTP.q(domain))&include_subdomains=true&expand=dns_names")
            do {
                let raw = try await HTTP.json(url, timeout: 30)
                for row in (raw as? [[String: Any]]) ?? [] { for n in row.strs("dns_names") { names.insert(clean(n)) } }
            } catch { throw crtError ?? error }
        }
        return names.filter { $0.hasSuffix(domain) && !$0.isEmpty && TargetParser.isValidHostname($0) }.sorted()
    }

    static func clean(_ s: String) -> String {
        var n = s.lowercased().trimmed()
        if n.hasPrefix("*.") { n.removeFirst(2) }
        return n
    }

    public static func run(_ domain: String, resolve: Bool = true, ctx: ToolContext = .silent) async throws -> ToolOutput {
        let names = try await subdomains(of: domain, ctx: ctx)
        var out = ToolOutput()
        if resolve {
            ctx.log("Resolving \(names.count) names…")
            let hits = await Subdomains.resolve(Array(names.prefix(400)), source: "ct-logs")
            out.sections = [Subdomains.section(hits, title: "Certificate Transparency subdomains")]
            out.findings += await Subdomains.takeoverCandidates(hits)
        } else {
            out.sections = [ReportSection("Certificate Transparency subdomains (\(names.count))", items: names.map { ReportItem($0, "") })]
        }
        return out
    }
}

// MARK: - Wayback Machine

public enum Wayback {
    static let interesting = [".env", ".git", ".sql", ".bak", ".old", ".zip", ".tar", ".gz", ".log", ".config", ".yml", ".yaml",
                              ".pem", ".key", "id_rsa", "backup", "admin", "login", "api/", "swagger", "debug", "internal",
                              "token", "secret", "password", "passwd", "config", "dump", "phpinfo", "upload", "console"]

    public static func urls(for domain: String, limit: Int = 3000) async throws -> [String] {
        let url = try HTTP.url("https://web.archive.org/cdx/search/cdx?url=*.\(HTTP.q(domain))&output=json&fl=original&collapse=urlkey&limit=\(limit)")
        let raw = try await HTTP.json(url, timeout: 60, maxBytes: 20_000_000)
        guard let rows = raw as? [[String]] else { return [] }
        return rows.dropFirst().compactMap { $0.first }
    }

    public static func run(_ domain: String) async throws -> ToolOutput {
        let all = try await urls(for: domain)
        var out = ToolOutput()

        let hosts = Set(all.compactMap { URL(string: $0)?.host?.lowercased() }.map { $0.hasPrefix("www.") && false ? $0 : $0 })
        let juicy = all.filter { u in let l = u.lowercased(); return interesting.contains { l.contains($0) } }
        let withParams = all.filter { $0.contains("?") && $0.contains("=") }

        var summary = ReportSection("Wayback Machine – \(domain)")
        summary.add("Archived URLs (sampled)", "\(all.count)")
        summary.add("Distinct hosts", "\(hosts.count)")
        summary.add("Interesting URLs", "\(juicy.count)", juicy.isEmpty ? .info : .low)
        summary.add("URLs with parameters", "\(withParams.count)")

        var hs = ReportSection("Hosts seen in archive (\(hosts.count))")
        for h in hosts.sorted().prefix(150) { hs.add(h, "") }

        var js = ReportSection("Interesting archived URLs (\(juicy.count))",
                               note: "Archived content may no longer exist but reveals historical endpoints, backups and admin paths.")
        for u in Array(Set(juicy)).sorted().prefix(120) {
            let l = u.lowercased()
            let sev: Severity = [".env", ".git", ".sql", ".pem", "id_rsa", "passwd", "dump"].contains { l.contains($0) } ? .medium : .info
            js.add("", u, sev)
            if sev == .medium { out.findings.append(Finding(.medium, "Sensitive-looking URL in web archive", u, source: "wayback")) }
        }

        var ps = ReportSection("Parameterised endpoints (injection candidates)")
        for u in Array(Set(withParams)).sorted().prefix(60) { ps.add("", u) }

        out.sections = [summary, hs, js, ps]
        return out
    }
}

// MARK: - Reverse IP (virtual hosts on same address)

public enum ReverseIP {
    public static func run(_ ip: String) async throws -> ToolOutput {
        let url = try HTTP.url("https://api.hackertarget.com/reverseiplookup/?q=\(HTTP.q(ip))")
        let r = try await HTTP.request(url, timeout: 20)
        let text = r.text.trimmed()
        var s = ReportSection("Domains hosted on \(ip)", note: "Source: hackertarget.com free API (rate-limited).")
        if text.lowercased().hasPrefix("error") || text.contains("API count exceeded") || text.contains("No records") {
            s.add("Result", text.isEmpty ? "no data" : text, .low)
        } else {
            for d in text.split(separator: "\n").map(String.init).sorted() { s.add("", d) }
        }
        return ToolOutput(sections: [s])
    }
}
