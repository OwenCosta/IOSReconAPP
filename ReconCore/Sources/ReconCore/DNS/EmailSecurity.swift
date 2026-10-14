import Foundation

/// SPF / DMARC / DKIM / MTA-STS / DNSSEC / CAA posture for a domain.
public enum EmailSecurity {
    static let dkimSelectors = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
                                "s1", "s2", "smtp", "mandrill", "mxvault", "zoho", "protonmail", "everlytickey1"]

    public struct SPF: Sendable, Equatable {
        public var record: String
        public var all: String?        // "-all", "~all", "?all", "+all"
        public var includes: [String]
    }

    public static func parseSPF(_ txt: String) -> SPF? {
        guard txt.lowercased().hasPrefix("v=spf1") else { return nil }
        let terms = txt.split(separator: " ").map(String.init)
        let all = terms.first { $0.lowercased().hasSuffix("all") && $0.count <= 4 }
        let inc = terms.filter { $0.lowercased().hasPrefix("include:") }.map { String($0.dropFirst(8)) }
        return SPF(record: txt, all: all.map { $0.count == 3 ? "+all" : $0.lowercased() }, includes: inc)
    }

    public static func parseTags(_ record: String) -> [String: String] {
        var out: [String: String] = [:]
        for part in record.split(separator: ";") {
            let kv = part.split(separator: "=", maxSplits: 1).map { String($0).trimmed() }
            if kv.count == 2 { out[kv[0].lowercased()] = kv[1] }
        }
        return out
    }

    public static func analyze(_ domain: String) async -> ToolOutput {
        var out = ToolOutput()
        async let txt = DNSClient.records(domain, .TXT)
        async let mx = DNSClient.records(domain, .MX)
        async let dmarcTXT = DNSClient.records("_dmarc.\(domain)", .TXT)
        async let mtaSTS = DNSClient.records("_mta-sts.\(domain)", .TXT)
        async let tlsrpt = DNSClient.records("_smtp._tls.\(domain)", .TXT)
        async let bimi = DNSClient.records("default._bimi.\(domain)", .TXT)
        async let caa = DNSClient.records(domain, .CAA)
        async let dnskeyAnswer = try? DNSClient.query(domain, type: .A, dnssec: true)
        let selectorHits = await boundedMap(dkimSelectors, limit: 8) { sel -> String? in
            let r = await DNSClient.records("\(sel)._domainkey.\(domain)", .TXT)
            return r.contains { $0.data.lowercased().contains("p=") } ? sel : nil
        }.compactMap { $0 }

        let txtRecords = await txt, mxRecords = await mx

        var mail = ReportSection("Mail routing")
        if mxRecords.isEmpty { mail.add("MX", "none (domain does not receive mail)", .info) }
        for r in mxRecords { mail.add("MX", r.data) }

        var sec = ReportSection("Email authentication")
        let spfRecords = txtRecords.compactMap { parseSPF($0.data) }
        if let spf = spfRecords.first {
            var sev: Severity = .info
            var verdict = "strict (-all)"
            switch spf.all {
            case "-all": break
            case "~all": sev = .low; verdict = "softfail (~all) – spoofed mail is flagged, not rejected"
            case "?all": sev = .medium; verdict = "neutral (?all) – SPF gives no protection"
            case "+all": sev = .critical; verdict = "+all – ANYONE may send as this domain"
            default:
                if spf.record.lowercased().contains("redirect=") { verdict = "uses redirect= (policy delegated to another domain)" }
                else { sev = .medium; verdict = "no terminating 'all' mechanism" }
            }
            if spfRecords.count > 1 { sec.add("SPF", "multiple SPF records (invalid per RFC 7208)", .medium) }
            sec.add("SPF", verdict, sev)
            sec.add("SPF record", spf.record)
            if spf.includes.count > 6 { sec.add("SPF lookups", "\(spf.includes.count) includes – risk of exceeding the 10 DNS-lookup limit", .low) }
            if sev >= .low { out.findings.append(Finding(sev, "Weak SPF policy on \(domain)", verdict, source: "email")) }
        } else if !mxRecords.isEmpty {
            sec.add("SPF", "missing", .medium)
            out.findings.append(Finding(.medium, "No SPF record on \(domain)", "Domain handles mail but publishes no SPF policy.", source: "email"))
        } else {
            sec.add("SPF", "missing (no MX, null-sender recommended: v=spf1 -all)", .low)
        }

        if let dm = await dmarcTXT.first(where: { $0.data.lowercased().hasPrefix("v=dmarc1") }) {
            let tags = parseTags(dm.data)
            let policy = tags["p"]?.lowercased() ?? "none"
            var sev: Severity = .info
            if policy == "none" { sev = .medium } else if policy == "quarantine" { sev = .low }
            sec.add("DMARC policy", "p=\(policy)" + (tags["pct"].map { " pct=\($0)" } ?? ""), sev)
            if let sp = tags["sp"] { sec.add("DMARC subdomain policy", "sp=\(sp)") }
            sec.add("DMARC reports", tags["rua"] ?? "no rua= aggregate reporting", tags["rua"] == nil ? .low : .info)
            if sev >= .medium {
                out.findings.append(Finding(.medium, "DMARC is monitor-only on \(domain)", "p=none does not stop spoofing.", source: "email"))
            }
        } else {
            sec.add("DMARC", "missing", .medium)
            out.findings.append(Finding(.medium, "No DMARC record on \(domain)", "Spoofed mail is not subject to any alignment policy.", source: "email"))
        }

        sec.add("DKIM selectors found", selectorHits.isEmpty ? "none of \(dkimSelectors.count) common selectors" : selectorHits.joined(separator: ", "),
                selectorHits.isEmpty ? .low : .info)
        sec.add("MTA-STS", (await mtaSTS).isEmpty ? "not published" : "published", (await mtaSTS).isEmpty ? .low : .info)
        sec.add("TLS-RPT", (await tlsrpt).isEmpty ? "not published" : "published")
        sec.add("BIMI", (await bimi).isEmpty ? "not published" : "published")

        var dns = ReportSection("DNS hardening")
        let caaRecs = await caa
        dns.add("CAA", caaRecs.isEmpty ? "no CAA – any CA may issue certificates" : caaRecs.map(\.data).joined(separator: "; "),
                caaRecs.isEmpty ? .low : .info)
        let signed = (await dnskeyAnswer)?.authenticated ?? false
        dns.add("DNSSEC", signed ? "validated (AD bit set)" : "not validated / not signed", signed ? .info : .low)

        out.sections = [mail, sec, dns]
        return out
    }
}
