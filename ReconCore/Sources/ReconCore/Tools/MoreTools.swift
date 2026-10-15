import Foundation

// MARK: - HTTP request sender (a phone-friendly curl / mini-Postman)

/// Sends an arbitrary HTTP request typed in a simple text format and shows the
/// full response. For testing your own / authorised APIs and web apps on the go.
///
/// Input format:
///   METHOD https://host/path        (or just a URL → GET)
///   Header-Name: value              (zero or more header lines)
///   <blank line>
///   request body (optional)
public enum HTTPRequester {
    public struct Parsed: Equatable {
        public var method: String
        public var url: String
        public var headers: [(String, String)]
        public var body: String?
        public static func == (a: Parsed, b: Parsed) -> Bool {
            a.method == b.method && a.url == b.url && a.body == b.body &&
            a.headers.map { "\($0.0)=\($0.1)" } == b.headers.map { "\($0.0)=\($0.1)" }
        }
    }

    public static func parse(_ input: String) -> Parsed? {
        // Split off the body at the first blank line.
        let normalized = input.replacingOccurrences(of: "\r\n", with: "\n")
        var head = normalized
        var body: String?
        if let r = normalized.range(of: "\n\n") {
            head = String(normalized[normalized.startIndex..<r.lowerBound])
            let b = String(normalized[r.upperBound...])
            body = b.isEmpty ? nil : b
        }
        var lines = head.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard let first = lines.first.map({ $0.trimmed() }), !first.isEmpty else { return nil }
        lines.removeFirst()

        var method = "GET"
        var urlToken = first
        let parts = first.split(separator: " ", maxSplits: 1).map { $0.trimmed() }
        let verbs = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        if parts.count == 2, verbs.contains(parts[0].uppercased()) {
            method = parts[0].uppercased()
            urlToken = parts[1]
        }
        if !urlToken.contains("://") { urlToken = "https://" + urlToken }

        var headers: [(String, String)] = []
        for line in lines {
            let t = line.trimmed()
            if t.isEmpty { continue }
            guard let c = t.firstIndex(of: ":") else { continue }
            let name = String(t[t.startIndex..<c]).trimmed()
            let value = String(t[t.index(after: c)...]).trimmed()
            if !name.isEmpty { headers.append((name, value)) }
        }
        return Parsed(method: method, url: urlToken, headers: headers, body: body)
    }

    public static func run(_ input: String) async -> ToolOutput {
        guard let p = parse(input), let url = URL(string: p.url) else {
            return ToolOutput(sections: [ReportSection("HTTP request", items: [
                ReportItem("Usage", "METHOD url, then header lines, a blank line, then an optional body.", .low),
                ReportItem("Example", "POST https://httpbin.org/post\\nContent-Type: application/json\\n\\n{\"a\":1}", .info)
            ])])
        }
        var hdrs = [String: String]()
        for (k, v) in p.headers { hdrs[k] = v }
        let bodyData = p.body.map { Data($0.utf8) }
        do {
            let r = try await HTTP.request(url, method: p.method, headers: hdrs, body: bodyData,
                                           timeout: 20, followRedirects: false, maxBytes: 2_000_000)
            var out = ToolOutput()
            var meta = ReportSection("\(p.method) \(url.absoluteString)")
            meta.add("Status", "\(r.status) \(statusText(r.status))", severityFor(r.status))
            meta.add("Time", String(format: "%.0f ms", r.elapsed * 1000))
            meta.add("Size", "\(r.body.count) bytes")
            if let loc = r.headers["location"] { meta.add("↪ Location", loc, .low) }
            out.sections.append(meta)

            var hs = ReportSection("Response headers (\(r.headers.count))")
            for (k, v) in r.headers.sorted(by: { $0.key < $1.key }) { hs.add(k, v) }
            out.sections.append(hs)

            let text = r.text
            if !text.isEmpty {
                let preview = String(text.prefix(6000))
                var bs = ReportSection("Body", note: text.count > 6000 ? "showing first 6000 of \(text.count) chars" : nil)
                bs.add("", preview)
                out.sections.append(bs)
            }
            return out
        } catch {
            return ToolOutput(sections: [ReportSection("HTTP request", items: [
                ReportItem("\(p.method) \(url.absoluteString)", "", .info),
                ReportItem("Error", (error as? ReconError)?.errorDescription ?? "\(error)", .high)
            ])])
        }
    }

    static func severityFor(_ status: Int) -> Severity {
        switch status {
        case 200..<300: return .low
        case 300..<400: return .info
        case 400..<500: return .medium
        default: return .high
        }
    }

    static func statusText(_ c: Int) -> String {
        switch c {
        case 200: return "OK"; case 201: return "Created"; case 204: return "No Content"
        case 301: return "Moved Permanently"; case 302: return "Found"; case 304: return "Not Modified"
        case 400: return "Bad Request"; case 401: return "Unauthorized"; case 403: return "Forbidden"
        case 404: return "Not Found"; case 405: return "Method Not Allowed"; case 429: return "Too Many Requests"
        case 500: return "Internal Server Error"; case 502: return "Bad Gateway"; case 503: return "Service Unavailable"
        default: return ""
        }
    }
}

// MARK: - WAF-bypass payload encoder chains

/// Takes one payload (XSS / SQLi / path / command) and renders the common
/// encodings used to smuggle it past filters and WAFs on authorised tests.
public enum PayloadEncoder {
    /// Percent-encode every byte (not just reserved ones).
    public static func fullPercent(_ s: String) -> String {
        s.utf8.map { String(format: "%%%02X", $0) }.joined()
    }
    /// Classic double URL-encoding: %3C → %253C (hex digits preserved).
    public static func doublePercent(_ s: String) -> String {
        fullPercent(s).replacingOccurrences(of: "%", with: "%25")
    }
    public static func htmlDecimal(_ s: String) -> String {
        s.unicodeScalars.map { "&#\($0.value);" }.joined()
    }
    public static func htmlHex(_ s: String) -> String {
        s.unicodeScalars.map { String(format: "&#x%x;", $0.value) }.joined()
    }
    public static func unicodeEscape(_ s: String) -> String {
        s.unicodeScalars.map { $0.value <= 0xFFFF ? String(format: "\\u%04x", $0.value) : String(format: "\\u{%x}", $0.value) }.joined()
    }
    public static func hexEscape(_ s: String) -> String {
        s.utf8.map { String(format: "\\x%02x", $0) }.joined()
    }
    public static func mixedCase(_ s: String) -> String {
        var upper = true
        var out = ""
        for ch in s {
            if ch.isLetter { out.append(upper ? Character(ch.uppercased()) : Character(ch.lowercased())); upper.toggle() }
            else { out.append(ch) }
        }
        return out
    }
    /// Replace spaces with inline SQL comments to beat naive space filters.
    public static func sqlComment(_ s: String) -> String {
        s.replacingOccurrences(of: " ", with: "/**/")
    }

    public static func run(_ input: String) -> ToolOutput {
        let p = input.trimmed()
        guard !p.isEmpty else {
            return ToolOutput(sections: [ReportSection("Payload encoder", items: [
                ReportItem("Usage", "paste a payload, e.g. <script>alert(1)</script> or ' OR 1=1-- -", .low)])])
        }
        var s = ReportSection("Encodings: \(p.prefix(60))", note: "For getting an authorised payload past input filters / WAFs. Try each where the app decodes once or twice.")
        s.add("URL (full)", fullPercent(p))
        s.add("URL (double)", doublePercent(p))
        s.add("HTML decimal", htmlDecimal(p))
        s.add("HTML hex", htmlHex(p))
        s.add("Unicode \\u", unicodeEscape(p))
        s.add("Hex \\x", hexEscape(p))
        s.add("Base64", Data(p.utf8).base64EncodedString())
        s.add("Base64 URL", Data(p.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: ""))
        s.add("Mixed case", mixedCase(p))
        s.add("SQL /**/ spaces", sqlComment(p))
        return ToolOutput(sections: [s])
    }
}

// MARK: - CeWL-style wordlist generator

/// Builds a custom wordlist from the text of a page — the vocabulary a target
/// actually uses, which often seeds better password / parameter guesses than a
/// generic list.
public enum WordlistGen {
    /// Extract candidate words from raw HTML/text: strip tags, keep word-ish tokens.
    public static func words(from html: String, minLength: Int = 4, maxLength: Int = 24) -> [(word: String, count: Int)] {
        // Remove script/style blocks and tags.
        var text = html
        for pat in ["(?s)<script.*?</script>", "(?s)<style.*?</style>", "<[^>]+>"] {
            text = text.replacingOccurrences(of: pat, with: " ", options: .regularExpression)
        }
        text = decodeBasicEntities(text)
        var counts: [String: Int] = [:]
        var order: [String] = []
        let tokens = text.components(separatedBy: CharacterSet.alphanumerics.inverted)
        for raw in tokens {
            let w = raw.trimmed()
            guard w.count >= minLength, w.count <= maxLength else { continue }
            guard w.first?.isLetter == true else { continue }          // skip pure numbers
            let key = w.lowercased()
            if counts[key] == nil { order.append(key) }
            counts[key, default: 0] += 1
        }
        return order.map { ($0, counts[$0] ?? 0) }
            .sorted { $0.count != $1.count ? $0.count > $1.count : $0.word < $1.word }
    }

    static func decodeBasicEntities(_ s: String) -> String {
        s.replacingOccurrences(of: "&amp;", with: "&")
         .replacingOccurrences(of: "&lt;", with: "<")
         .replacingOccurrences(of: "&gt;", with: ">")
         .replacingOccurrences(of: "&quot;", with: "\"")
         .replacingOccurrences(of: "&#39;", with: "'")
         .replacingOccurrences(of: "&nbsp;", with: " ")
    }

    public static func run(_ input: String) async -> ToolOutput {
        // Optional "url :: minLength"
        let parts = input.components(separatedBy: "::")
        let urlInput = parts[0].trimmed()
        let minLen = parts.count > 1 ? max(3, Int(parts[1].trimmed()) ?? 4) : 4
        guard let base = WebRecon.normalizeURL(urlInput) else {
            return ToolOutput(sections: [ReportSection("Wordlist", items: [
                ReportItem("Usage", "enter a URL (optionally  url :: 5  to set the minimum word length)", .low)])])
        }
        guard let r = try? await HTTP.request(base, timeout: 20, maxBytes: 3_000_000), !r.body.isEmpty else {
            return ToolOutput(sections: [ReportSection("Wordlist", items: [
                ReportItem("Result", "could not fetch \(base.absoluteString)", .medium)])])
        }
        let ranked = words(from: r.text, minLength: minLen)
        guard !ranked.isEmpty else {
            return ToolOutput(sections: [ReportSection("Wordlist", items: [ReportItem("Result", "no words found", .low)])])
        }
        var out = ToolOutput()
        var top = ReportSection("Top words (\(ranked.count) unique)", note: "From \(base.host ?? base.absoluteString). Min length \(minLen). Feed into password spraying or content discovery on authorised targets.")
        for (w, c) in ranked.prefix(120) { top.add("×\(c)", w) }
        out.sections.append(top)
        // A copy-paste block of just the words (most useful as a list).
        var list = ReportSection("Plain list (top 200)")
        list.add("", ranked.prefix(200).map(\.word).joined(separator: "\n"))
        out.sections.append(list)
        return out
    }
}
