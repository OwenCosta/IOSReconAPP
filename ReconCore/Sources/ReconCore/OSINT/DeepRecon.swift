import Foundation

// MARK: - MurmurHash3 x86 32-bit (for Shodan favicon pivoting)

public enum MurmurHash3 {
    public static func hash32(_ data: [UInt8], seed: UInt32 = 0) -> Int32 {
        let c1: UInt32 = 0xcc9e2d51, c2: UInt32 = 0x1b873593
        var h = seed
        let nblocks = data.count / 4
        for i in 0..<nblocks {
            var k = UInt32(data[i*4]) | (UInt32(data[i*4+1]) << 8) | (UInt32(data[i*4+2]) << 16) | (UInt32(data[i*4+3]) << 24)
            k = k &* c1; k = (k << 15) | (k >> 17); k = k &* c2
            h ^= k; h = (h << 13) | (h >> 19); h = h &* 5 &+ 0xe6546b64
        }
        var k1: UInt32 = 0
        let tail = nblocks * 4
        switch data.count & 3 {
        case 3: k1 ^= UInt32(data[tail+2]) << 16; fallthrough
        case 2: k1 ^= UInt32(data[tail+1]) << 8; fallthrough
        case 1: k1 ^= UInt32(data[tail]); k1 = k1 &* c1; k1 = (k1 << 15) | (k1 >> 17); k1 = k1 &* c2; h ^= k1
        default: break
        }
        h ^= UInt32(data.count)
        h ^= h >> 16; h = h &* 0x85ebca6b; h ^= h >> 13; h = h &* 0xc2b2ae35; h ^= h >> 16
        return Int32(bitPattern: h)
    }
}

/// Shodan-style favicon hash: base64 (MIME, 76-char lines, LF, trailing LF) then MurmurHash3.
public enum FaviconHash {
    public static func hash(_ data: Data) -> Int32 {
        let raw = data.base64EncodedString()
        var chunked = ""
        var i = raw.startIndex
        while i < raw.endIndex {
            let end = raw.index(i, offsetBy: 76, limitedBy: raw.endIndex) ?? raw.endIndex
            chunked += raw[i..<end] + "\n"
            i = end
        }
        return MurmurHash3.hash32([UInt8](chunked.utf8))
    }

    public static func run(_ input: String) async -> ToolOutput {
        guard let base = WebRecon.normalizeURL(input) else {
            return ToolOutput(sections: [ReportSection("Favicon hash", items: [ReportItem("Usage", "enter a URL or domain", .low)])])
        }
        let url = URL(string: "/favicon.ico", relativeTo: base)?.absoluteURL ?? base
        guard let r = try? await HTTP.request(url, timeout: 12, maxBytes: 2_000_000), r.status == 200, !r.body.isEmpty else {
            return ToolOutput(sections: [ReportSection("Favicon hash", items: [ReportItem("Result", "no favicon found at \(url.absoluteString)", .low)])])
        }
        let h = hash(r.body)
        var s = ReportSection("Favicon hash", note: "Pivot: find other hosts serving the same favicon, often the same org or software.")
        s.add("Shodan hash", "\(h)")
        s.add("Shodan query", "http.favicon.hash:\(h)")
        s.add("Censys query", "services.http.response.favicons.md5_hash (see Censys docs)")
        s.add("Size", "\(r.body.count) bytes")
        s.add("MD5", Digests.hex(.md5, r.body) ?? "")
        return ToolOutput(sections: [s])
    }
}

// MARK: - JS / endpoint extraction

public enum EndpointExtractor {
    static let pattern = #"(?:"|'|`)((?:[a-zA-Z]{1,10}://|//)[^"'`\s]{3,}|/(?:[A-Za-z0-9_\-./%]{2,})(?:\?[^"'`\s]*)?|[A-Za-z0-9_\-/]{1,}\.(?:php|asp|aspx|jsp|do|action|json|xml|js|txt|bak|sql|config|env|yml|yaml)(?:\?[^"'`\s]*)?)(?:"|'|`)"#

    public static func extract(from text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        var seen = Set<String>()
        var out: [String] = []
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let s = ns.substring(with: m.range(at: 1)).trimmed()
            // skip noise
            if s.count < 3 || s.hasPrefix("//fonts.") { continue }
            if s.contains(" ") { continue }
            if seen.insert(s).inserted { out.append(s) }
        }
        return out
    }

    public static func classify(_ endpoints: [String]) -> (urls: [String], paths: [String], interesting: [String]) {
        var urls: [String] = [], paths: [String] = [], interesting: [String] = []
        let juicy = ["api", "admin", "token", "secret", "key", "upload", "debug", "internal", "graphql", "swagger",
                     "user", "login", "auth", "config", ".env", "backup", "private", "/v1/", "/v2/", "password"]
        for e in endpoints {
            let l = e.lowercased()
            if juicy.contains(where: { l.contains($0) }) { interesting.append(e) }
            if e.contains("://") || e.hasPrefix("//") { urls.append(e) } else { paths.append(e) }
        }
        return (urls, paths, interesting)
    }

    public static func run(_ input: String) async -> ToolOutput {
        var text = input
        // If it's a URL, fetch the page + its scripts; otherwise treat the input as the blob.
        if let url = WebRecon.normalizeURL(input), input.contains(".") && !input.contains(" ") && !input.contains("\n") {
            if let probe = try? await WebRecon.fetch(url) {
                var bodies = [probe.final.text]
                if let re = try? NSRegularExpression(pattern: #"<script[^>]+src=[\"']([^\"']+\.js[^\"']*)[\"']"#, options: [.caseInsensitive]) {
                    let ns = probe.final.text as NSString
                    var urls: [URL] = []
                    for m in re.matches(in: probe.final.text, range: NSRange(location: 0, length: ns.length)).prefix(15) {
                        if let u = URL(string: ns.substring(with: m.range(at: 1)), relativeTo: probe.finalURL)?.absoluteURL { urls.append(u) }
                    }
                    bodies += await boundedMap(urls, limit: 6) { (try? await HTTP.request($0, timeout: 10, maxBytes: 3_000_000))?.text ?? "" }
                }
                text = bodies.joined(separator: "\n")
            }
        }
        let eps = extract(from: text)
        let (urls, paths, interesting) = classify(eps)
        var out = ToolOutput()
        var s = ReportSection("Endpoints (\(eps.count))", note: "Extracted from the page and its JavaScript. Great for finding hidden APIs and paths to probe next.")
        if !interesting.isEmpty {
            var hot = ReportSection("Interesting (\(interesting.count))")
            for e in interesting.prefix(80) { hot.add("", e, .medium) }
            out.sections.append(hot)
            out.findings.append(Finding(.low, "\(interesting.count) interesting endpoints extracted", interesting.prefix(8).joined(separator: ", "), source: "endpoints"))
        }
        for u in urls.prefix(100) { s.add("url", u) }
        for p in paths.prefix(150) { s.add("path", p) }
        if eps.isEmpty { s.add("Result", "no endpoints found") }
        out.sections.append(s)
        return out
    }
}

// MARK: - Google dork generator

public enum Dorks {
    public static func forDomain(_ domain: String) -> [(String, String)] {
        let d = domain
        return [
            ("All indexed pages", "site:\(d)"),
            ("Non-www hosts", "site:\(d) -www"),
            ("Documents", "site:\(d) (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx)"),
            ("Config / data files", "site:\(d) (ext:env OR ext:ini OR ext:conf OR ext:cnf OR ext:yml OR ext:json OR ext:xml OR ext:log OR ext:bak OR ext:sql)"),
            ("Admin / login panels", "site:\(d) (inurl:admin OR inurl:login OR inurl:dashboard OR inurl:portal OR inurl:signin)"),
            ("Directory listings", "site:\(d) intitle:\"index of\""),
            ("Parameters (injection)", "site:\(d) (inurl:?id= OR inurl:?page= OR inurl:?file= OR inurl:?search=)"),
            ("Exposed WordPress", "site:\(d) inurl:wp-content"),
            ("Backup / test subdomains", "site:\(d) (inurl:dev OR inurl:test OR inurl:staging OR inurl:beta)"),
            ("Credentials / secrets", "site:\(d) (intext:password OR intext:\"api_key\" OR intext:secret OR intext:\"BEGIN RSA\")"),
            ("Open redirects", "site:\(d) (inurl:redirect OR inurl:url= OR inurl:return=)"),
            ("Error messages", "site:\(d) (intext:\"sql syntax\" OR intext:\"stack trace\" OR intext:\"fatal error\")"),
            ("On Pastebin", "site:pastebin.com \(d)"),
            ("On GitHub", "site:github.com \(d)"),
            ("Cloud storage", "(site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com) \(d)"),
            ("Code search (GitHub)", "\"\(d)\" (password OR api_key OR secret OR token)")
        ]
    }

    public static func run(_ input: String) -> ToolOutput {
        guard let d = TargetParser.domain(from: input) else {
            return ToolOutput(sections: [ReportSection("Google dorks", items: [ReportItem("Usage", "enter a domain, e.g. example.com", .low)])])
        }
        var s = ReportSection("Google dorks: \(d)", note: "Paste each into Google (or Bing). Passive OSINT against the search index, not the target.")
        for (label, dork) in forDomain(d) { s.add(label, dork) }
        return ToolOutput(sections: [s])
    }
}
