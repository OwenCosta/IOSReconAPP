import Foundation

/// Services that need the user's own API key (supplied via `SecretsProvider`) plus the key-less
/// k-anonymity password check.
public enum KeyedServices {

    // MARK: Have I Been Pwned – account breaches

    public static func hibpAccount(_ email: String, key: String) async -> ToolOutput {
        var s = ReportSection("Have I Been Pwned – breaches")
        var out = ToolOutput()
        guard let url = URL(string: "https://haveibeenpwned.com/api/v3/breachedaccount/\(HTTP.q(email))?truncateResponse=false") else { return out }
        do {
            let r = try await HTTP.request(url, headers: ["hibp-api-key": key], timeout: 15)
            switch r.status {
            case 200:
                let list = ((try? JSONSerialization.jsonObject(with: r.body)) as? [[String: Any]]) ?? []
                s.add("Breaches", "\(list.count)", list.isEmpty ? .info : .high)
                for b in list.sorted(by: { ($0.str("BreachDate") ?? "") > ($1.str("BreachDate") ?? "") }) {
                    let classes = b.strs("DataClasses").joined(separator: ", ")
                    let sensitive = classes.lowercased().contains("password")
                    s.add(b.str("Name") ?? "?", "\(b.str("BreachDate") ?? "") · \(classes)", sensitive ? .high : .medium)
                }
                if !list.isEmpty {
                    out.findings.append(Finding(.high, "\(email) found in \(list.count) data breach(es)",
                                                list.prefix(8).compactMap { $0.str("Name") }.joined(separator: ", "), source: "hibp"))
                }
            case 404: s.add("Breaches", "none found")
            case 401: s.add("Error", "API key rejected", .medium)
            case 429: s.add("Error", "rate limited", .low)
            default: s.add("Error", "HTTP \(r.status)", .low)
            }
        } catch { s.add("Error", error.localizedDescription, .low) }
        out.sections = [s]
        return out
    }

    // MARK: Pwned Passwords – k-anonymity range API (no key)

    /// Only the first 5 hex chars of the SHA-1 leave the device.
    public static func pwnedPassword(_ password: String) async throws -> ToolOutput {
        guard !password.isEmpty else { throw ReconError.invalidInput("enter a password") }
        guard let sha = Digests.hex(.sha1, password)?.uppercased() else { throw ReconError.unsupported("SHA-1 unavailable on this platform") }
        let prefix = String(sha.prefix(5)), suffix = String(sha.dropFirst(5))
        let r = try await HTTP.request(try HTTP.url("https://api.pwnedpasswords.com/range/\(prefix)"), headers: ["Add-Padding": "true"], timeout: 12)
        guard r.status == 200 else { throw ReconError.http(r.status) }
        var count = 0
        for line in r.text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":")
            if parts.count == 2, parts[0].uppercased() == suffix { count = Int(parts[1].trimmed()) ?? 0 }
        }
        var out = ToolOutput()
        var s = ReportSection("Password exposure")
        if count > 0 {
            s.add("Result", "Seen \(count) times in known breaches – do not use", .critical)
            out.findings.append(Finding(.critical, "Password appears in breach corpus (\(count)×)", "", source: "pwned"))
        } else {
            s.add("Result", "Not found in the Pwned Passwords corpus")
        }
        let bits = PasswordStrength.entropyBits(password)
        s.add("Estimated entropy", String(format: "%.0f bits (character-class estimate)", bits), bits < 40 ? .high : (bits < 60 ? .medium : .info))
        s.add("Privacy", "Only SHA-1 prefix \(prefix)… was sent (k-anonymity). The password never left this device.")
        out.sections = [s]
        return out
    }

    // MARK: Shodan (key)

    public static func shodanHost(_ ip: String, key: String) async -> ToolOutput {
        var s = ReportSection("Shodan host – \(ip)")
        var out = ToolOutput()
        do {
            let raw = try await HTTP.json(try HTTP.url("https://api.shodan.io/shodan/host/\(HTTP.q(ip))?key=\(HTTP.q(key))"), timeout: 20)
            guard let o = raw as? [String: Any] else { throw ReconError.parse("Shodan") }
            if let org = o.str("org") { s.add("Organisation", org) }
            if let os = o.str("os") { s.add("OS", os) }
            s.add("Hostnames", o.strs("hostnames").joined(separator: ", "))
            s.add("Last update", o.str("last_update") ?? "")
            let vulns = o.strs("vulns")
            if !vulns.isEmpty { s.add("CVEs", vulns.sorted().joined(separator: ", "), .high)
                out.findings.append(Finding(.high, "\(ip): \(vulns.count) CVE(s) per Shodan", vulns.sorted().prefix(15).joined(separator: ", "), source: "shodan")) }
            var svc = ReportSection("Shodan services")
            for d in o.dicts("data") {
                let port = d.int("port") ?? 0
                let product = [d.str("product"), d.str("version")].compactMap { $0 }.joined(separator: " ")
                svc.add("\(port)/\(d.str("transport") ?? "tcp")", product.isEmpty ? String((d.str("data") ?? "").prefix(120)) : product,
                        ServiceDB.risk(port: UInt16(clamping: port))?.severity ?? .info)
            }
            out.sections = [s, svc]
        } catch ReconError.http(let code) {
            s.add("Error", code == 404 ? "no information available for this IP" : (code == 401 ? "API key rejected" : "HTTP \(code)"), .low)
            out.sections = [s]
        } catch {
            s.add("Error", error.localizedDescription, .low)
            out.sections = [s]
        }
        return out
    }

    // MARK: VirusTotal (key)

    public static func virusTotal(_ target: String, key: String) async -> ToolOutput {
        let isIP = IPv4.isIP(target)
        var s = ReportSection("VirusTotal – \(target)")
        do {
            let raw = try await HTTP.json(try HTTP.url("https://www.virustotal.com/api/v3/\(isIP ? "ip_addresses" : "domains")/\(HTTP.q(target))"),
                                          headers: ["x-apikey": key], timeout: 20)
            let attrs = ((raw as? [String: Any])?.dict("data"))?.dict("attributes") ?? [:]
            let stats = attrs.dict("last_analysis_stats") ?? [:]
            let mal = stats.int("malicious") ?? 0, sus = stats.int("suspicious") ?? 0
            s.add("Detections", "\(mal) malicious · \(sus) suspicious · \(stats.int("harmless") ?? 0) harmless",
                  mal > 0 ? .high : (sus > 0 ? .medium : .info))
            if let rep = attrs.int("reputation") { s.add("Community reputation", "\(rep)", rep < 0 ? .medium : .info) }
            if let reg = attrs.str("registrar") { s.add("Registrar", reg) }
            if let own = attrs.str("as_owner") { s.add("AS owner", own) }
            if let cats = attrs.dict("categories") { s.add("Categories", Set(cats.values.compactMap { $0 as? String }).sorted().joined(separator: ", ")) }
            var out = ToolOutput(sections: [s])
            if mal > 0 { out.findings.append(Finding(.high, "\(target) flagged malicious by \(mal) engine(s) on VirusTotal", "", source: "virustotal")) }
            return out
        } catch ReconError.http(let code) {
            s.add("Error", code == 404 ? "not found" : (code == 401 || code == 403 ? "API key rejected" : "HTTP \(code)"), .low)
        } catch { s.add("Error", error.localizedDescription, .low) }
        return ToolOutput(sections: [s])
    }
}
