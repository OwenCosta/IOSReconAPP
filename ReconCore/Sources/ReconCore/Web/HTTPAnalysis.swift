import Foundation

public struct HTTPHop: Sendable {
    public var url: String
    public var status: Int
    public var location: String?
}

public struct HTTPProbe: Sendable {
    public var hops: [HTTPHop]
    public var final: HTTP.Response
    public var finalURL: URL
}

public struct Technology: Hashable, Sendable {
    public var name: String
    public var category: String
    public var version: String?
    public var evidence: String
}

public enum WebRecon {

    // MARK: Fetch with manual redirect tracking

    public static func normalizeURL(_ input: String) -> URL? {
        var s = input.trimmed()
        guard !s.isEmpty else { return nil }
        if !s.contains("://") { s = "https://" + s }
        guard let u = URL(string: s), let h = u.host, !h.isEmpty else { return nil }
        return u
    }

    public static func fetch(_ url: URL, maxRedirects: Int = 10, insecureTLS: Bool = false) async throws -> HTTPProbe {
        var current = url
        var hops: [HTTPHop] = []
        for _ in 0...maxRedirects {
            let r = try await HTTP.request(current, followRedirects: false, insecureTLS: insecureTLS)
            if (300..<400).contains(r.status), let loc = r.headers["location"],
               let next = URL(string: loc, relativeTo: current)?.absoluteURL {
                hops.append(HTTPHop(url: current.absoluteString, status: r.status, location: next.absoluteString))
                current = next
                continue
            }
            hops.append(HTTPHop(url: current.absoluteString, status: r.status, location: nil))
            return HTTPProbe(hops: hops, final: r, finalURL: current)
        }
        throw ReconError.network("too many redirects")
    }

    /// Try https first, fall back to http.
    public static func fetchAuto(_ input: String) async throws -> HTTPProbe {
        guard let url = normalizeURL(input) else { throw ReconError.invalidInput("bad URL") }
        if input.contains("://") { return try await fetch(url) }
        do { return try await fetch(url) }
        catch {
            var c = URLComponents(url: url, resolvingAgainstBaseURL: false)
            c?.scheme = "http"
            if let alt = c?.url, let probe = try? await fetch(alt) { return probe }
            throw error
        }
    }

    // MARK: Security header grading

    public struct HeaderGrade: Sendable {
        public var score: Int
        public var grade: String
        public var items: [ReportItem]
    }

    public static func gradeHeaders(_ h: [String: String], https: Bool) -> HeaderGrade {
        var score = 0
        var items: [ReportItem] = []

        func check(_ name: String, weight: Int, present: Bool, good: String, bad: String, badSeverity: Severity) {
            if present { score += weight; items.append(ReportItem(name, good)) }
            else { items.append(ReportItem(name, bad, badSeverity)) }
        }

        let csp = h["content-security-policy"]
        if let csp = csp {
            let weak = csp.contains("'unsafe-inline'") || csp.contains("'unsafe-eval'") || csp.contains(" * ")
            score += weak ? 15 : 25
            items.append(ReportItem("Content-Security-Policy", weak ? "present but allows unsafe-inline/eval/wildcards" : "present",
                                    weak ? .low : .info))
        } else {
            items.append(ReportItem("Content-Security-Policy", "missing – no defence-in-depth against XSS", .medium))
        }

        if https {
            if let hsts = h["strict-transport-security"] {
                let age = Int(hsts.lowercased().components(separatedBy: "max-age=").dropFirst().first?
                    .prefix(while: { $0.isNumber }) ?? "") ?? 0
                if age >= 15_552_000 {
                    score += 20
                    items.append(ReportItem("Strict-Transport-Security", hsts +
                        (hsts.lowercased().contains("includesubdomains") ? "" : "  (no includeSubDomains)")))
                } else {
                    score += 8
                    items.append(ReportItem("Strict-Transport-Security", "max-age too short (\(age)s): \(hsts)", .low))
                }
            } else {
                items.append(ReportItem("Strict-Transport-Security", "missing – downgrade / SSL-strip possible", .medium))
            }
        } else {
            items.append(ReportItem("Transport", "page served over plain HTTP", .high))
        }

        let frameOK = h["x-frame-options"] != nil || (csp?.contains("frame-ancestors") ?? false)
        check("Clickjacking protection", weight: 15, present: frameOK, good: h["x-frame-options"] ?? "CSP frame-ancestors",
              bad: "missing X-Frame-Options / frame-ancestors", badSeverity: .low)
        check("X-Content-Type-Options", weight: 10, present: h["x-content-type-options"]?.lowercased() == "nosniff",
              good: "nosniff", bad: "missing nosniff", badSeverity: .low)
        check("Referrer-Policy", weight: 10, present: h["referrer-policy"] != nil,
              good: h["referrer-policy"] ?? "", bad: "missing – URLs may leak via Referer", badSeverity: .low)
        check("Permissions-Policy", weight: 10, present: h["permissions-policy"] != nil || h["feature-policy"] != nil,
              good: "present", bad: "missing", badSeverity: .info)
        check("Cross-Origin isolation", weight: 10,
              present: h["cross-origin-opener-policy"] != nil || h["cross-origin-resource-policy"] != nil,
              good: "COOP/CORP set", bad: "no COOP/CORP", badSeverity: .info)

        let grade: String
        switch score {
        case 90...: grade = "A"
        case 75..<90: grade = "B"
        case 60..<75: grade = "C"
        case 40..<60: grade = "D"
        default: grade = "F"
        }
        return HeaderGrade(score: score, grade: grade, items: items)
    }

    // MARK: Information disclosure & cookies

    public static func infoLeaks(_ h: [String: String]) -> [ReportItem] {
        var out: [ReportItem] = []
        let versioned = try? NSRegularExpression(pattern: #"[A-Za-z\-_ ]+[/ ]\d+(\.\d+)+"#)
        func hasVersion(_ s: String) -> Bool {
            versioned?.firstMatch(in: s, range: NSRange(location: 0, length: (s as NSString).length)) != nil
        }
        for key in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache",
                    "x-runtime", "x-version", "x-backend-server", "x-debug-token", "x-debug-token-link", "via"] {
            guard let v = h[key] else { continue }
            let sev: Severity = (hasVersion(v) || key.hasPrefix("x-debug")) ? .low : .info
            out.append(ReportItem(key, v, sev))
        }
        return out
    }

    public static func auditCookies(_ cookies: [String], https: Bool) -> [ReportItem] {
        cookies.map { raw in
            let parts = raw.split(separator: ";").map { String($0).trimmed() }
            let name = parts.first?.split(separator: "=").first.map(String.init) ?? raw
            let flags = Set(parts.dropFirst().map { $0.lowercased() })
            var problems: [String] = []
            if https && !flags.contains("secure") { problems.append("no Secure") }
            if !flags.contains("httponly") { problems.append("no HttpOnly") }
            if !flags.contains(where: { $0.hasPrefix("samesite") }) { problems.append("no SameSite") }
            else if flags.contains("samesite=none") && !flags.contains("secure") { problems.append("SameSite=None without Secure") }
            let session = name.lowercased().contains("sess") || name.lowercased().contains("auth") || name.lowercased().contains("token")
            let sev: Severity = problems.isEmpty ? .info : (session ? .medium : .low)
            return ReportItem(name, problems.isEmpty ? "Secure, HttpOnly, SameSite" : problems.joined(separator: ", "), sev)
        }
    }

    // MARK: Technology fingerprinting

    private struct Rule {
        enum Where { case header(String), body, cookie, url }
        let name: String
        let category: String
        let place: Where
        let pattern: String
    }

    private static let rules: [Rule] = [
        // servers & platforms
        .init(name: "nginx", category: "Web server", place: .header("server"), pattern: #"(?i)nginx(?:/([\d.]+))?"#),
        .init(name: "Apache httpd", category: "Web server", place: .header("server"), pattern: #"(?i)apache(?:/([\d.]+))?"#),
        .init(name: "Microsoft IIS", category: "Web server", place: .header("server"), pattern: #"(?i)microsoft-iis(?:/([\d.]+))?"#),
        .init(name: "LiteSpeed", category: "Web server", place: .header("server"), pattern: #"(?i)litespeed"#),
        .init(name: "Caddy", category: "Web server", place: .header("server"), pattern: #"(?i)caddy"#),
        .init(name: "Envoy", category: "Proxy", place: .header("server"), pattern: #"(?i)envoy"#),
        .init(name: "Cloudflare", category: "CDN / WAF", place: .header("server"), pattern: #"(?i)cloudflare"#),
        .init(name: "Cloudflare", category: "CDN / WAF", place: .header("cf-ray"), pattern: #".+"#),
        .init(name: "Amazon CloudFront", category: "CDN", place: .header("x-amz-cf-id"), pattern: #".+"#),
        .init(name: "Amazon S3", category: "Storage", place: .header("server"), pattern: #"(?i)AmazonS3"#),
        .init(name: "Akamai", category: "CDN", place: .header("server"), pattern: #"(?i)akamai"#),
        .init(name: "Fastly", category: "CDN", place: .header("x-served-by"), pattern: #"(?i)cache-"#),
        .init(name: "Varnish", category: "Cache", place: .header("x-varnish"), pattern: #".+"#),
        .init(name: "Vercel", category: "Hosting", place: .header("server"), pattern: #"(?i)vercel"#),
        .init(name: "Netlify", category: "Hosting", place: .header("server"), pattern: #"(?i)netlify"#),
        .init(name: "GitHub Pages", category: "Hosting", place: .header("server"), pattern: #"(?i)GitHub\.com"#),
        .init(name: "Sucuri WAF", category: "WAF", place: .header("x-sucuri-id"), pattern: #".+"#),
        .init(name: "Imperva Incapsula", category: "WAF", place: .header("x-iinfo"), pattern: #".+"#),
        // languages / frameworks
        .init(name: "PHP", category: "Language", place: .header("x-powered-by"), pattern: #"(?i)php(?:/([\d.]+))?"#),
        .init(name: "ASP.NET", category: "Framework", place: .header("x-powered-by"), pattern: #"(?i)asp\.net"#),
        .init(name: "ASP.NET", category: "Framework", place: .header("x-aspnet-version"), pattern: #"([\d.]+)"#),
        .init(name: "Express", category: "Framework", place: .header("x-powered-by"), pattern: #"(?i)express"#),
        .init(name: "Next.js", category: "Framework", place: .header("x-powered-by"), pattern: #"(?i)next\.js(?:\s*([\d.]+))?"#),
        .init(name: "Next.js", category: "Framework", place: .body, pattern: #"__NEXT_DATA__|/_next/static/"#),
        .init(name: "Nuxt", category: "Framework", place: .body, pattern: #"__NUXT__|/_nuxt/"#),
        .init(name: "React", category: "JS library", place: .body, pattern: #"data-reactroot|react(?:\.production)?\.min\.js|__REACT_DEVTOOLS"#),
        .init(name: "Vue.js", category: "JS library", place: .body, pattern: #"data-v-[0-9a-f]{6,}|vue(?:\.runtime)?(?:\.min)?\.js"#),
        .init(name: "Angular", category: "JS library", place: .body, pattern: #"ng-version=\"([\d.]+)\"|<app-root"#),
        .init(name: "jQuery", category: "JS library", place: .body, pattern: #"jquery[-.]?(?:min\.)?(\d+\.\d+\.\d+)?(?:\.min)?\.js"#),
        .init(name: "Bootstrap", category: "UI", place: .body, pattern: #"bootstrap(?:\.min)?\.(?:css|js)|bootstrap/(\d+\.\d+\.\d+)"#),
        .init(name: "Tailwind CSS", category: "UI", place: .body, pattern: #"tailwind"#),
        .init(name: "Laravel", category: "Framework", place: .cookie, pattern: #"laravel_session|XSRF-TOKEN"#),
        .init(name: "Django", category: "Framework", place: .cookie, pattern: #"csrftoken|django"#),
        .init(name: "Ruby on Rails", category: "Framework", place: .cookie, pattern: #"_rails|_session_id"#),
        .init(name: "Ruby on Rails", category: "Framework", place: .body, pattern: #"csrf-param\" content=\"authenticity_token"#),
        .init(name: "Spring", category: "Framework", place: .cookie, pattern: #"JSESSIONID"#),
        .init(name: "PHP session", category: "Language", place: .cookie, pattern: #"PHPSESSID"#),
        .init(name: "ASP.NET session", category: "Framework", place: .cookie, pattern: #"ASP\.NET_SessionId|\.ASPXAUTH"#),
        // CMS & commerce
        .init(name: "WordPress", category: "CMS", place: .body, pattern: #"wp-content/|wp-includes/|<meta name=\"generator\" content=\"WordPress ?([\d.]+)?"#),
        .init(name: "Drupal", category: "CMS", place: .body, pattern: #"Drupal\.settings|sites/(?:all|default)/(?:modules|themes)|<meta name=\"Generator\" content=\"Drupal ([\d.]+)"#),
        .init(name: "Joomla", category: "CMS", place: .body, pattern: #"/media/jui/|<meta name=\"generator\" content=\"Joomla!? ?([\d.]+)?"#),
        .init(name: "Ghost", category: "CMS", place: .body, pattern: #"<meta name=\"generator\" content=\"Ghost ?([\d.]+)?"#),
        .init(name: "Shopify", category: "E-commerce", place: .body, pattern: #"cdn\.shopify\.com|Shopify\.theme"#),
        .init(name: "Magento", category: "E-commerce", place: .body, pattern: #"Mage\.Cookies|/static/frontend/Magento"#),
        .init(name: "WooCommerce", category: "E-commerce", place: .body, pattern: #"woocommerce"#),
        .init(name: "Wix", category: "Builder", place: .body, pattern: #"static\.wixstatic\.com|X-Wix-"#),
        .init(name: "Squarespace", category: "Builder", place: .body, pattern: #"static1\.squarespace\.com|Squarespace"#),
        .init(name: "Webflow", category: "Builder", place: .body, pattern: #"data-wf-site|webflow\.js"#),
        // third parties
        .init(name: "Google Analytics", category: "Analytics", place: .body, pattern: #"google-analytics\.com|googletagmanager\.com|gtag\("#),
        .init(name: "Google reCAPTCHA", category: "Security", place: .body, pattern: #"recaptcha/api\.js"#),
        .init(name: "hCaptcha", category: "Security", place: .body, pattern: #"hcaptcha\.com"#),
        .init(name: "Stripe", category: "Payments", place: .body, pattern: #"js\.stripe\.com"#),
        .init(name: "Sentry", category: "Monitoring", place: .body, pattern: #"sentry(?:-cdn)?\.(?:io|com)|Sentry\.init"#),
        .init(name: "Hotjar", category: "Analytics", place: .body, pattern: #"static\.hotjar\.com"#)
    ]

    public static func fingerprint(headers: [String: String], cookies: [String], body: String) -> [Technology] {
        var found: [String: Technology] = [:]
        let cookieBlob = cookies.joined(separator: "\n")
        let sample = String(body.prefix(400_000))
        for rule in rules {
            let subject: String
            switch rule.place {
            case .header(let h): guard let v = headers[h] else { continue }; subject = v
            case .body: subject = sample
            case .cookie: subject = cookieBlob
            case .url: continue
            }
            guard let re = try? NSRegularExpression(pattern: rule.pattern) else { continue }
            let ns = subject as NSString
            guard let m = re.firstMatch(in: subject, range: NSRange(location: 0, length: ns.length)) else { continue }
            var version: String?
            if m.numberOfRanges > 1, m.range(at: 1).location != NSNotFound {
                let v = ns.substring(with: m.range(at: 1))
                if !v.isEmpty { version = v }
            }
            let evidence: String
            switch rule.place {
            case .header(let h): evidence = "header \(h)"
            case .body: evidence = "page source"
            case .cookie: evidence = "cookie"
            case .url: evidence = "url"
            }
            if let existing = found[rule.name], existing.version != nil || version == nil { continue }
            found[rule.name] = Technology(name: rule.name, category: rule.category, version: version, evidence: evidence)
        }
        return found.values.sorted { ($0.category, $0.name) < ($1.category, $1.name) }
    }

    public static func title(of html: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: #"<title[^>]*>([^<]{1,200})</title>"#, options: [.caseInsensitive]) else { return nil }
        let ns = html as NSString
        guard let m = re.firstMatch(in: html, range: NSRange(location: 0, length: min(ns.length, 200_000))) else { return nil }
        return ns.substring(with: m.range(at: 1)).trimmed()
    }

    // MARK: Composite report

    public static func analyze(_ input: String) async throws -> ToolOutput {
        let probe = try await fetchAuto(input)
        let https = probe.finalURL.scheme == "https"
        let h = probe.final.headers
        var out = ToolOutput()

        var overview = ReportSection("Response")
        overview.add("Final URL", probe.finalURL.absoluteString)
        overview.add("Status", "\(probe.final.status)")
        overview.add("Time", String(format: "%.0f ms", probe.final.elapsed * 1000))
        overview.add("Size", ByteCountFormatter.string(fromByteCount: Int64(probe.final.body.count), countStyle: .file))
        if let t = title(of: probe.final.text) { overview.add("Title", t) }
        if let ct = h["content-type"] { overview.add("Content-Type", ct) }
        if !https { overview.items[0].severity = .high }

        var chain = ReportSection("Redirect chain")
        for (i, hop) in probe.hops.enumerated() {
            chain.add("\(i + 1). \(hop.status)", hop.url + (hop.location.map { "\n→ \($0)" } ?? ""))
        }
        if let first = probe.hops.first, first.url.hasPrefix("http://"),
           !(probe.hops.contains { $0.url.hasPrefix("https://") }) {
            out.findings.append(Finding(.high, "Site is served over HTTP only", first.url, source: "web"))
        }

        let g = gradeHeaders(h, https: https)
        var hdr = ReportSection("Security headers – grade \(g.grade) (\(g.score)/100)")
        hdr.items = g.items
        if g.grade == "D" || g.grade == "F" {
            out.findings.append(Finding(.medium, "Weak HTTP security headers (grade \(g.grade))", probe.finalURL.host ?? "", source: "web"))
        } else if g.grade == "C" {
            out.findings.append(Finding(.low, "Mediocre HTTP security headers (grade C)", probe.finalURL.host ?? "", source: "web"))
        }

        var leaks = ReportSection("Information disclosure headers")
        leaks.items = infoLeaks(h)
        if leaks.items.isEmpty { leaks.add("Headers", "no version banners exposed") }
        for item in leaks.items where item.severity >= .low {
            out.findings.append(Finding(.low, "Version disclosure: \(item.label)", item.value, source: "web"))
        }

        var cookieSec = ReportSection("Cookies")
        cookieSec.items = auditCookies(probe.final.setCookies, https: https)
        if cookieSec.items.isEmpty { cookieSec.add("Set-Cookie", "none set on first response") }
        for item in cookieSec.items where item.severity >= .medium {
            out.findings.append(Finding(.medium, "Insecure cookie flags: \(item.label)", item.value, source: "web"))
        }

        var techSec = ReportSection("Technology fingerprint")
        let techs = fingerprint(headers: h, cookies: probe.final.setCookies, body: probe.final.text)
        for t in techs { techSec.add(t.category, t.name + (t.version.map { " \($0)" } ?? "") + "   (\(t.evidence))") }
        if techs.isEmpty { techSec.add("Result", "nothing identified") }

        var allHeaders = ReportSection("All response headers")
        for (k, v) in h.sorted(by: { $0.key < $1.key }) { allHeaders.add(k, v) }

        out.sections = [overview, chain, hdr, leaks, cookieSec, techSec, allHeaders]
        return out
    }
}
