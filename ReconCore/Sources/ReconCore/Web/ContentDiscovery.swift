import Foundation

/// Checks a curated list of high-value paths (exposed VCS dirs, env files, debug consoles, admin panels).
/// Uses content signatures so catch-all servers that answer 200 for everything don't produce noise.
public enum ContentDiscovery {
    struct Probe {
        let path: String
        let severity: Severity
        let title: String
        /// Returns true when the response really is what the path implies.
        let verify: @Sendable (Int, String, [String: String]) -> Bool
    }

    static func contains(_ needles: String...) -> @Sendable (Int, String, [String: String]) -> Bool {
        { status, body, _ in status == 200 && needles.contains { body.contains($0) } }
    }
    static let anyOK: @Sendable (Int, String, [String: String]) -> Bool = { s, _, _ in s == 200 }
    static let exists: @Sendable (Int, String, [String: String]) -> Bool = { s, _, _ in [200, 401, 403].contains(s) }

    static let probes: [Probe] = [
        Probe(path: "/.git/HEAD", severity: .critical, title: "Exposed .git repository", verify: contains("ref: refs/")),
        Probe(path: "/.git/config", severity: .critical, title: "Exposed .git/config", verify: contains("[core]", "[remote")),
        Probe(path: "/.svn/entries", severity: .high, title: "Exposed Subversion metadata", verify: { s, b, _ in s == 200 && (b.hasPrefix("10") || b.contains("dir")) && !b.contains("<html") }),
        Probe(path: "/.hg/requires", severity: .high, title: "Exposed Mercurial repo", verify: contains("revlogv1", "store")),
        Probe(path: "/.env", severity: .critical, title: "Exposed .env file", verify: { s, b, _ in
            s == 200 && !b.lowercased().contains("<html") && b.contains("=") && (b.contains("KEY") || b.contains("DB_") || b.contains("SECRET") || b.contains("PASSWORD") || b.contains("APP_")) }),
        Probe(path: "/.env.production", severity: .critical, title: "Exposed production env file", verify: { s, b, _ in s == 200 && !b.lowercased().contains("<html") && b.contains("=") }),
        Probe(path: "/.aws/credentials", severity: .critical, title: "Exposed AWS credentials", verify: contains("aws_access_key_id")),
        Probe(path: "/.DS_Store", severity: .low, title: "Exposed .DS_Store (directory listing leak)", verify: { s, b, _ in s == 200 && b.contains("Bud1") }),
        Probe(path: "/.htpasswd", severity: .high, title: "Exposed .htpasswd", verify: { s, b, _ in s == 200 && b.contains(":$") || b.contains(":{SHA}") }),
        Probe(path: "/wp-config.php.bak", severity: .critical, title: "WordPress config backup", verify: contains("DB_PASSWORD", "DB_NAME")),
        Probe(path: "/web.config", severity: .high, title: "Readable web.config", verify: contains("<configuration")),
        Probe(path: "/phpinfo.php", severity: .high, title: "phpinfo() page", verify: contains("PHP Version", "phpinfo()")),
        Probe(path: "/info.php", severity: .high, title: "phpinfo() page", verify: contains("PHP Version", "phpinfo()")),
        Probe(path: "/server-status", severity: .medium, title: "Apache server-status", verify: contains("Apache Server Status")),
        Probe(path: "/server-info", severity: .medium, title: "Apache server-info", verify: contains("Apache Server Information")),
        Probe(path: "/actuator/env", severity: .high, title: "Spring Boot actuator /env", verify: contains("propertySources", "activeProfiles")),
        Probe(path: "/actuator/heapdump", severity: .critical, title: "Spring Boot heapdump", verify: { s, _, h in s == 200 && (h["content-type"] ?? "").contains("octet") }),
        Probe(path: "/actuator/health", severity: .info, title: "Spring Boot actuator", verify: contains("\"status\"")),
        Probe(path: "/console", severity: .high, title: "Werkzeug / debug console", verify: contains("Werkzeug", "Interactive Console")),
        Probe(path: "/elmah.axd", severity: .high, title: "ELMAH error log", verify: contains("Error Log for")),
        Probe(path: "/trace.axd", severity: .high, title: "ASP.NET trace", verify: contains("Application Trace")),
        Probe(path: "/_profiler", severity: .medium, title: "Symfony profiler", verify: contains("Symfony Profiler")),
        Probe(path: "/swagger.json", severity: .low, title: "Swagger/OpenAPI spec", verify: contains("\"swagger\"", "\"openapi\"")),
        Probe(path: "/openapi.json", severity: .low, title: "OpenAPI spec", verify: contains("\"openapi\"")),
        Probe(path: "/swagger-ui.html", severity: .low, title: "Swagger UI", verify: contains("swagger-ui", "Swagger UI")),
        Probe(path: "/api-docs", severity: .low, title: "API docs", verify: contains("\"swagger\"", "\"openapi\"", "swagger")),
        Probe(path: "/graphql", severity: .low, title: "GraphQL endpoint", verify: { s, b, _ in [200, 400, 405].contains(s) && (b.contains("graphql") || b.contains("GraphQL") || b.contains("Must provide query")) }),
        Probe(path: "/wp-json/wp/v2/users", severity: .medium, title: "WordPress user enumeration via REST", verify: { s, b, _ in s == 200 && b.hasPrefix("[") && b.contains("\"slug\"") }),
        Probe(path: "/wp-login.php", severity: .info, title: "WordPress login", verify: contains("user_login", "wp-submit")),
        Probe(path: "/xmlrpc.php", severity: .low, title: "WordPress XML-RPC enabled", verify: { s, b, _ in b.contains("XML-RPC server accepts POST requests only") }),
        Probe(path: "/administrator/", severity: .info, title: "Joomla admin", verify: contains("Joomla")),
        Probe(path: "/admin", severity: .info, title: "Admin panel path", verify: exists),
        Probe(path: "/login", severity: .info, title: "Login page", verify: anyOK),
        Probe(path: "/phpmyadmin/", severity: .medium, title: "phpMyAdmin exposed", verify: contains("phpMyAdmin")),
        Probe(path: "/backup.zip", severity: .high, title: "Backup archive", verify: { s, _, h in s == 200 && ((h["content-type"] ?? "").contains("zip") || (h["content-type"] ?? "").contains("octet")) }),
        Probe(path: "/backup.sql", severity: .critical, title: "SQL dump", verify: contains("INSERT INTO", "CREATE TABLE")),
        Probe(path: "/dump.sql", severity: .critical, title: "SQL dump", verify: contains("INSERT INTO", "CREATE TABLE")),
        Probe(path: "/database.sql", severity: .critical, title: "SQL dump", verify: contains("INSERT INTO", "CREATE TABLE")),
        Probe(path: "/docker-compose.yml", severity: .medium, title: "docker-compose file", verify: contains("services:")),
        Probe(path: "/Dockerfile", severity: .low, title: "Dockerfile", verify: contains("FROM ")),
        Probe(path: "/package.json", severity: .low, title: "package.json", verify: contains("\"dependencies\"", "\"scripts\"")),
        Probe(path: "/composer.json", severity: .low, title: "composer.json", verify: contains("\"require\"")),
        Probe(path: "/crossdomain.xml", severity: .low, title: "crossdomain.xml", verify: contains("cross-domain-policy")),
        Probe(path: "/robots.txt", severity: .info, title: "robots.txt", verify: contains("User-agent", "Disallow", "user-agent")),
        Probe(path: "/sitemap.xml", severity: .info, title: "sitemap.xml", verify: contains("<urlset", "<sitemapindex")),
        Probe(path: "/.well-known/security.txt", severity: .info, title: "security.txt", verify: contains("Contact:")),
        Probe(path: "/security.txt", severity: .info, title: "security.txt", verify: contains("Contact:"))
    ]

    public struct Result: Sendable {
        public var path: String
        public var title: String
        public var severity: Severity
        public var status: Int
        public var size: Int
        public var excerpt: String
    }

    public static func scan(base: URL, ctx: ToolContext = .silent) async -> [Result] {
        guard var comps = URLComponents(url: base, resolvingAgainstBaseURL: false) else { return [] }
        comps.path = ""; comps.query = nil; comps.fragment = nil
        guard let root = comps.url else { return [] }

        // Soft-404 calibration: what does a path that cannot exist look like?
        let canary = "/\(UUID().uuidString.prefix(12).lowercased())-recon"
        let soft = try? await HTTP.request(root.appendingPathComponent(canary), timeout: 8, followRedirects: false, maxBytes: 20_000)
        let catchAll = soft?.status == 200

        let results = await boundedMap(probes, limit: 6) { p -> Result? in
            guard let url = URL(string: p.path, relativeTo: root)?.absoluteURL,
                  let r = try? await HTTP.request(url, timeout: 8, followRedirects: false, maxBytes: 60_000) else { return nil }
            let body = r.text
            guard p.verify(r.status, body, r.headers) else { return nil }
            if catchAll, soft?.body.count == r.body.count, p.severity == .info { return nil }
            ctx.log("Found \(p.path) [\(r.status)]")
            let excerpt = String(body.prefix(160)).replacingOccurrences(of: "\n", with: " ")
            return Result(path: p.path, title: p.title, severity: p.severity, status: r.status, size: r.body.count, excerpt: excerpt)
        }
        return results.compactMap { $0 }.sorted { ($0.severity, $1.path) > ($1.severity, $0.path) }
    }

    public static func output(base: URL, ctx: ToolContext = .silent) async -> ToolOutput {
        let found = await scan(base: base, ctx: ctx)
        var out = ToolOutput()
        var s = ReportSection("Content discovery – \(found.count) of \(probes.count) probes hit",
                              note: "Checked \(probes.count) well-known paths with content verification (soft-404 aware).")
        for r in found {
            s.add("\(r.path)  [\(r.status), \(r.size) B]", r.title + (r.excerpt.isEmpty ? "" : "\n\(r.excerpt)"), r.severity)
            if r.severity >= .medium {
                out.findings.append(Finding(r.severity, "\(r.title): \(base.host ?? "")\(r.path)", "HTTP \(r.status), \(r.size) bytes", source: "web"))
            }
        }
        if found.isEmpty { s.add("Result", "no exposed paths from the curated list") }
        out.sections = [s]
        return out
    }
}

/// Reflected-origin CORS misconfiguration check.
public enum CORSCheck {
    public static func run(_ input: String) async throws -> ToolOutput {
        guard let url = WebRecon.normalizeURL(input) else { throw ReconError.invalidInput("bad URL") }
        var out = ToolOutput()
        var s = ReportSection("CORS policy – \(url.host ?? "")")
        let origins = ["https://evil.example", "null", "https://\(url.host ?? "x").evil.example"]
        for origin in origins {
            let r = try await HTTP.request(url, headers: ["Origin": origin], timeout: 10, followRedirects: true, maxBytes: 20_000)
            let acao = r.headers["access-control-allow-origin"]
            let acac = r.headers["access-control-allow-credentials"]?.lowercased() == "true"
            if let a = acao {
                let reflected = a == origin
                var sev: Severity = .info
                var verdict = "ACAO: \(a)"
                if reflected && acac { sev = .critical; verdict += "  + credentials=true → any origin can read authenticated responses" }
                else if reflected { sev = .medium; verdict += "  (origin reflected)" }
                else if a == "*" && acac { sev = .medium; verdict += "  (wildcard with credentials – browsers block, but misconfigured)" }
                else if a == "*" { sev = .low }
                s.add("Origin: \(origin)", verdict, sev)
                if sev >= .medium {
                    out.findings.append(Finding(sev, "Permissive CORS on \(url.host ?? "")", "Origin '\(origin)' → \(verdict)", source: "web"))
                }
            } else {
                s.add("Origin: \(origin)", "no CORS headers (not allowed)")
            }
        }
        out.sections = [s]
        return out
    }
}
