import Foundation

/// Aggregates subdomains from several free passive sources, so discovery no longer depends on a
/// single flaky endpoint or a brute-force wordlist. Each source has a pure, unit-tested parser.
public enum SubdomainSources {

    // MARK: Pure parsers (testable without network)

    public static func clean(_ s: String, domain: String) -> String? {
        var n = s.lowercased().trimmed()
        while n.hasPrefix("*.") { n.removeFirst(2) }
        if let at = n.lastIndex(of: "@") { n = String(n[n.index(after: at)...]) }
        if n.hasSuffix(".") { n.removeLast() }
        guard !n.isEmpty, n == domain || n.hasSuffix("." + domain),
              TargetParser.isValidHostname(n) else { return nil }
        return n
    }

    public static func parseCrtsh(_ data: Data, domain: String) -> Set<String> {
        guard let rows = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] else { return [] }
        var out = Set<String>()
        for row in rows {
            let field = (row["name_value"] as? String) ?? ""
            for part in field.split(whereSeparator: { $0 == "\n" || $0 == "," }) {
                if let c = clean(String(part), domain: domain) { out.insert(c) }
            }
            if let cn = row["common_name"] as? String, let c = clean(cn, domain: domain) { out.insert(c) }
        }
        return out
    }

    public static func parseCertspotter(_ data: Data, domain: String) -> Set<String> {
        guard let rows = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] else { return [] }
        var out = Set<String>()
        for row in rows {
            for n in (row["dns_names"] as? [Any])?.compactMap({ $0 as? String }) ?? [] {
                if let c = clean(n, domain: domain) { out.insert(c) }
            }
        }
        return out
    }

    /// jldc.me/anubis and similar return a flat JSON array of names.
    public static func parseJSONArray(_ data: Data, domain: String) -> Set<String> {
        guard let arr = (try? JSONSerialization.jsonObject(with: data)) as? [Any] else { return [] }
        var out = Set<String>()
        for item in arr { if let s = item as? String, let c = clean(s, domain: domain) { out.insert(c) } }
        return out
    }

    /// AlienVault OTX passive DNS: { "passive_dns": [ { "hostname": "x.example.com" } ] }
    public static func parseOTX(_ data: Data, domain: String) -> Set<String> {
        guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let rows = obj["passive_dns"] as? [[String: Any]] else { return [] }
        var out = Set<String>()
        for row in rows {
            if let h = (row["hostname"] as? String) ?? (row["address"] as? String), let c = clean(h, domain: domain) { out.insert(c) }
        }
        return out
    }

    /// HackerTarget hostsearch returns "hostname,ip" lines of plain text.
    public static func parseHostLines(_ text: String, domain: String) -> Set<String> {
        var out = Set<String>()
        for line in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let host = line.split(separator: ",").first.map(String.init) ?? String(line)
            if let c = clean(host, domain: domain) { out.insert(c) }
        }
        return out
    }

    // MARK: Network sources (best-effort; failures are swallowed so one dead source never blocks the rest)

    struct Source { let name: String; let fetch: @Sendable (String) async -> Set<String> }

    static func json(_ urlString: String, timeout: TimeInterval = 20, maxBytes: Int = 25_000_000) async -> Data? {
        guard let url = URL(string: urlString), let r = try? await HTTP.request(url, timeout: timeout, maxBytes: maxBytes),
              (200..<300).contains(r.status) else { return nil }
        return r.body
    }

    static let sources: [Source] = [
        Source(name: "crt.sh") { d in
            guard let data = await json("https://crt.sh/?q=%25.\(HTTP.q(d))&output=json", timeout: 40) else { return [] }
            return parseCrtsh(data, domain: d)
        },
        Source(name: "CertSpotter") { d in
            guard let data = await json("https://api.certspotter.com/v1/issuances?domain=\(HTTP.q(d))&include_subdomains=true&expand=dns_names") else { return [] }
            return parseCertspotter(data, domain: d)
        },
        Source(name: "HackerTarget") { d in
            guard let url = URL(string: "https://api.hackertarget.com/hostsearch/?q=\(HTTP.q(d))"),
                  let r = try? await HTTP.request(url, timeout: 20), (200..<300).contains(r.status) else { return [] }
            return parseHostLines(r.text, domain: d)
        },
        Source(name: "Anubis") { d in
            guard let data = await json("https://jldc.me/anubis/subdomains/\(HTTP.q(d))") else { return [] }
            return parseJSONArray(data, domain: d)
        },
        Source(name: "AlienVault OTX") { d in
            guard let data = await json("https://otx.alienvault.com/api/v1/indicators/domain/\(HTTP.q(d))/passive_dns") else { return [] }
            return parseOTX(data, domain: d)
        },
        Source(name: "RapidDNS") { d in
            guard let url = URL(string: "https://rapiddns.io/subdomain/\(HTTP.q(d))?full=1"),
                  let r = try? await HTTP.request(url, timeout: 25, maxBytes: 8_000_000), (200..<300).contains(r.status) else { return [] }
            return scrapeHostnames(r.text, domain: d)
        }
    ]

    /// Pull anything that looks like <sub>.<domain> out of an HTML/text blob.
    public static func scrapeHostnames(_ text: String, domain: String) -> Set<String> {
        let escaped = NSRegularExpression.escapedPattern(for: domain)
        guard let re = try? NSRegularExpression(pattern: "[A-Za-z0-9_](?:[A-Za-z0-9_\\-]*\\.)+" + escaped, options: [.caseInsensitive]) else { return [] }
        let ns = text as NSString
        var out = Set<String>()
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            if let c = clean(ns.substring(with: m.range), domain: domain) { out.insert(c) }
        }
        return out
    }

    /// Everything we can find passively, with per-source attribution.
    public static func enumerate(domain: String, ctx: ToolContext = .silent) async -> (names: [String], perSource: [(String, Int)]) {
        let results = await withTaskGroup(of: (String, Set<String>).self) { group -> [(String, Set<String>)] in
            for s in sources {
                group.addTask {
                    let found = await s.fetch(domain)
                    ctx.log("\(s.name): \(found.count) names")
                    return (s.name, found)
                }
            }
            var acc: [(String, Set<String>)] = []
            for await r in group { acc.append(r) }
            return acc
        }
        var union = Set<String>()
        for (_, set) in results { union.formUnion(set) }
        // Also fold in Wayback hostnames if available.
        if let urls = try? await Wayback.urls(for: domain, limit: 1500) {
            for u in urls { if let h = URL(string: u)?.host, let c = clean(h, domain: domain) { union.insert(c) } }
        }
        let perSource = results.map { ($0.0, $0.1.count) }.sorted { $0.0 < $1.0 }
        return (union.sorted(), perSource)
    }

    /// Full passive enumeration → resolve → takeover check, as a report. Optionally add a DoH brute pass.
    public static func run(_ domain: String, brute: Bool = false, ctx: ToolContext = .silent) async -> ToolOutput {
        ctx.log("Querying \(sources.count) passive sources for \(domain)…")
        let (passive, perSource) = await enumerate(domain: domain, ctx: ctx)
        var names = Set(passive)
        if brute {
            ctx.log("Adding DoH brute-force of \(Wordlist.subdomains.count) names…")
            for h in await Subdomains.bruteForce(domain: domain, ctx: ctx) { names.insert(h.name) }
        }
        ctx.log("Resolving \(names.count) unique hostnames…")
        let hits = await Subdomains.resolve(Array(names).sorted(), source: "passive")

        var out = ToolOutput()
        var summary = ReportSection("Sources", note: "Merged results from public passive-DNS and certificate sources.")
        for (name, count) in perSource { summary.add(name, "\(count) names") }
        summary.add("Total unique", "\(names.count)")
        summary.add("Resolving", "\(hits.filter { !$0.ips.isEmpty }.count)")
        out.sections.append(summary)
        out.sections.append(Subdomains.section(hits, title: "Subdomains"))
        out.findings += await Subdomains.takeoverCandidates(hits)
        if names.isEmpty {
            out.sections.append(ReportSection("No results", items: [
                ReportItem("Hint", "Nothing public was found. A brand-new or private-only subdomain may never appear in CT logs or passive DNS — try the brute-force tool, or check the exact name directly in DNS Records.", .low)]))
        }
        return out
    }
}
