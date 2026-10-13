import Foundation

// MARK: - RDAP (modern WHOIS)

public enum RDAP {
    static let iso = ISO8601DateFormatter()

    public static func domain(_ name: String) async throws -> ToolOutput {
        let url = try HTTP.url("https://rdap.org/domain/\(HTTP.q(name))")
        let raw = try await HTTP.json(url, headers: ["Accept": "application/rdap+json"], timeout: 20)
        guard let o = raw as? [String: Any] else { throw ReconError.parse("RDAP") }
        var out = ToolOutput()
        var s = ReportSection("Registration – \(o.str("ldhName") ?? name)")
        if let h = o.str("handle") { s.add("Handle", h) }
        let status = o.strs("status")
        if !status.isEmpty { s.add("Status", status.joined(separator: ", ")) }

        var registered: Date?, expires: Date?
        for e in o.dicts("events") {
            guard let action = e.str("eventAction"), let ds = e.str("eventDate") else { continue }
            let date = iso.date(from: ds)
            var sev: Severity = .info
            if action == "registration", let d = date {
                registered = d
                let age = Int(-d.timeIntervalSinceNow / 86400)
                if age < 30 { sev = .medium }
                s.add("Registered", ds + "  (\(age) days old)", sev)
                if age < 30 {
                    out.findings.append(Finding(.medium, "Newly registered domain (\(age) days)", "Young domains are common in phishing infrastructure.", source: "whois"))
                }
                continue
            }
            if action == "expiration", let d = date {
                expires = d
                let left = Int(d.timeIntervalSinceNow / 86400)
                if left < 0 { sev = .high } else if left < 30 { sev = .low }
                s.add("Expires", ds + "  (\(left) days)", sev)
                continue
            }
            s.add(action.capitalized, ds)
        }
        _ = (registered, expires)

        for ent in o.dicts("entities") {
            let roles = ent.strs("roles")
            var name: String?
            if let vcard = ent.arr("vcardArray"), vcard.count > 1, let props = vcard[1] as? [Any] {
                for p in props {
                    if let arr = p as? [Any], arr.count > 3, (arr[0] as? String) == "fn" { name = arr[3] as? String }
                }
            }
            if let n = name, !roles.isEmpty { s.add(roles.joined(separator: "/").capitalized, n) }
        }
        let ns = o.dicts("nameservers").compactMap { $0.str("ldhName")?.lowercased() }
        if !ns.isEmpty { s.add("Nameservers", ns.joined(separator: "\n")) }
        if let sec = o.dict("secureDNS") {
            let signed = (sec["delegationSigned"] as? Bool) ?? false
            s.add("DNSSEC", signed ? "delegation signed" : "unsigned", signed ? .info : .low)
        }
        if status.contains(where: { $0.lowercased().contains("transfer prohibited") }) == false, !status.isEmpty {
            s.add("Lock", "no clientTransferProhibited – domain is not registrar-locked", .low)
        }
        out.sections = [s]
        return out
    }

    public static func ip(_ addr: String) async throws -> ToolOutput {
        let url = try HTTP.url("https://rdap.org/ip/\(HTTP.q(addr))")
        let raw = try await HTTP.json(url, headers: ["Accept": "application/rdap+json"], timeout: 20)
        guard let o = raw as? [String: Any] else { throw ReconError.parse("RDAP") }
        var s = ReportSection("Network allocation – \(addr)")
        if let n = o.str("name") { s.add("Network name", n) }
        if let h = o.str("handle") { s.add("Handle", h) }
        if let a = o.str("startAddress"), let b = o.str("endAddress") { s.add("Range", "\(a) – \(b)") }
        if let c = o.str("country") { s.add("Country", c) }
        if let t = o.str("type") { s.add("Type", t) }
        if let cidrs = o.dicts("cidr0_cidrs") as [[String: Any]]?, !cidrs.isEmpty {
            s.add("CIDR", cidrs.compactMap { c in
                guard let p = c.str("v4prefix") ?? c.str("v6prefix"), let l = c.int("length") else { return nil }
                return "\(p)/\(l)"
            }.joined(separator: ", "))
        }
        for ent in o.dicts("entities") {
            var name: String?
            if let vcard = ent.arr("vcardArray"), vcard.count > 1, let props = vcard[1] as? [Any] {
                for p in props { if let arr = p as? [Any], arr.count > 3, (arr[0] as? String) == "fn" { name = arr[3] as? String } }
            }
            if let n = name { s.add(ent.strs("roles").joined(separator: "/").capitalized, n) }
        }
        return ToolOutput(sections: [s])
    }
}

// MARK: - IP intelligence

public enum IPIntel {
    public struct Geo: Sendable {
        public var ip: String, country: String?, region: String?, city: String?, lat: Double?, lon: Double?
        public var asn: String?, org: String?, isp: String?, timezone: String?
    }

    public static func geo(_ ip: String?) async throws -> Geo {
        let url = try HTTP.url("https://ipwho.is/\(ip.map { HTTP.q($0) } ?? "")")
        let raw = try await HTTP.json(url, timeout: 12)
        guard let o = raw as? [String: Any], (o["success"] as? Bool) != false else { throw ReconError.parse("ipwho.is lookup failed") }
        let conn = o.dict("connection")
        return Geo(ip: o.str("ip") ?? ip ?? "", country: o.str("country"), region: o.str("region"), city: o.str("city"),
                   lat: (o["latitude"] as? NSNumber)?.doubleValue, lon: (o["longitude"] as? NSNumber)?.doubleValue,
                   asn: conn?.str("asn").map { "AS\($0)" }, org: conn?.str("org"), isp: conn?.str("isp"),
                   timezone: o.dict("timezone")?.str("id"))
    }

    public struct InternetDB: Sendable {
        public var ports: [Int], hostnames: [String], vulns: [String], tags: [String], cpes: [String]
    }

    /// Shodan's free, key-less InternetDB. 404 means "nothing known".
    public static func internetDB(_ ip: String) async -> InternetDB? {
        guard let url = URL(string: "https://internetdb.shodan.io/\(ip)"),
              let r = try? await HTTP.request(url, timeout: 12), r.status == 200,
              let o = (try? JSONSerialization.jsonObject(with: r.body)) as? [String: Any] else { return nil }
        return InternetDB(ports: (o["ports"] as? [Int]) ?? [], hostnames: o.strs("hostnames"),
                          vulns: o.strs("vulns"), tags: o.strs("tags"), cpes: o.strs("cpes"))
    }

    /// Everything we can say about one IP address, passively.
    public static func profile(_ ip: String) async -> ToolOutput {
        async let geoR = try? geo(ip)
        async let rdns = DNSClient.reverse(ip)
        async let idb = internetDB(ip)
        var out = ToolOutput()
        var s = ReportSection("IP profile – \(ip)")
        if let g = await geoR {
            s.add("Location", [g.city, g.region, g.country].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", "))
            if let a = g.asn { s.add("ASN", a) }
            if let o = g.org { s.add("Organisation", o) }
            if let i = g.isp, i != g.org { s.add("ISP", i) }
            if let la = g.lat, let lo = g.lon { s.add("Coordinates", String(format: "%.4f, %.4f", la, lo)) }
            if let tz = g.timezone { s.add("Timezone", tz) }
        }
        let ptr = await rdns
        s.add("Reverse DNS", ptr.isEmpty ? "none" : ptr.joined(separator: ", "))
        if let d = await idb {
            var p = ReportSection("Shodan InternetDB – \(ip)", note: "Passive data: no packets were sent to the target.")
            p.add("Known open ports", d.ports.isEmpty ? "none indexed" : d.ports.sorted().map { "\($0) (\(ServiceDB.name(port: UInt16(clamping: $0))))" }.joined(separator: ", "))
            for port in d.ports { if let r = ServiceDB.risk(port: UInt16(clamping: port)), r.severity >= .high {
                out.findings.append(Finding(r.severity, "\(ip): port \(port) indexed as open", r.why, source: "shodan")) } }
            if !d.hostnames.isEmpty { p.add("Hostnames", d.hostnames.joined(separator: "\n")) }
            if !d.tags.isEmpty { p.add("Tags", d.tags.joined(separator: ", "), d.tags.contains("compromised") || d.tags.contains("malware") ? .high : .info) }
            if !d.cpes.isEmpty { p.add("Software (CPE)", d.cpes.joined(separator: "\n")) }
            if !d.vulns.isEmpty {
                p.add("Potential CVEs (\(d.vulns.count))", d.vulns.sorted().joined(separator: ", "), .high)
                out.findings.append(Finding(.high, "\(ip) matches \(d.vulns.count) known CVE(s)", d.vulns.sorted().prefix(12).joined(separator: ", "), source: "shodan"))
            }
            out.sections = [s, p]
        } else {
            out.sections = [s]
        }
        return out
    }

    public static func myIP() async throws -> Geo { try await geo(nil) }
}
