import Foundation

public enum ToolCategory: String, CaseIterable, Sendable, Identifiable {
    case dns = "DNS", osint = "OSINT", web = "Web", network = "Network", utility = "Utilities"
    public var id: String { rawValue }
    public var icon: String {
        switch self {
        case .dns: return "point.3.connected.trianglepath.dotted"
        case .osint: return "eye"
        case .web: return "globe"
        case .network: return "network"
        case .utility: return "wrench.and.screwdriver"
        }
    }
}

public struct ToolSpec: Identifiable, Sendable {
    public let id: String
    public let title: String
    public let subtitle: String
    public let icon: String
    public let category: ToolCategory
    public let inputLabel: String
    public let placeholder: String
    /// Sends traffic to the target itself (as opposed to public third-party data sources).
    public let active: Bool
    public let secureInput: Bool
    public let inputOptional: Bool
    public let multiline: Bool
    public let requiresKey: String?
    public let run: @Sendable (String, ToolContext) async throws -> ToolOutput

    init(_ id: String, _ title: String, _ subtitle: String, icon: String, _ category: ToolCategory,
         input: String = "Target", placeholder: String = "example.com", active: Bool = false, secure: Bool = false,
         optional: Bool = false, multiline: Bool = false, key: String? = nil,
         run: @escaping @Sendable (String, ToolContext) async throws -> ToolOutput) {
        self.id = id; self.title = title; self.subtitle = subtitle; self.icon = icon; self.category = category
        self.inputLabel = input; self.placeholder = placeholder; self.active = active; self.secureInput = secure
        self.inputOptional = optional; self.multiline = multiline; self.requiresKey = key; self.run = run
    }
}

public enum ToolCatalog {
    static func domain(_ s: String) throws -> String {
        guard let d = TargetParser.domain(from: s) else { throw ReconError.invalidInput("enter a domain like example.com") }
        return d
    }
    static func hostOrIP(_ s: String) throws -> String {
        let h = TargetParser.stripToHost(s).lowercased()
        guard IPv4.isIP(h) || TargetParser.isValidHostname(h) else { throw ReconError.invalidInput("enter a hostname or IP") }
        return h
    }
    static func single(_ title: String, _ items: [ReportItem], note: String? = nil) -> ToolOutput {
        ToolOutput(sections: [ReportSection(title, items: items, note: note)])
    }

    public static var all: [ToolSpec] {
        var tools: [ToolSpec] = []

        // MARK: DNS
        tools.append(ToolSpec("dns-records", "DNS Records", "A, AAAA, CNAME, NS, MX, TXT, SOA, CAA over DoH", icon: "list.bullet.rectangle", .dns) { input, _ in
            let d = try hostOrIP(input)
            let recs = await DNSClient.allRecords(d)
            var s = ReportSection("DNS records – \(d) (\(recs.count))")
            for r in recs.sorted(by: { ($0.type, $0.data) < ($1.type, $1.data) }) { s.add(r.type, "\(r.data)   (TTL \(r.ttl))") }
            if recs.isEmpty { s.add("Result", "no records / NXDOMAIN", .low) }
            return ToolOutput(sections: [s])
        })
        tools.append(ToolSpec("reverse-dns", "Reverse DNS", "PTR lookup for an IP address", icon: "arrow.uturn.backward", .dns,
                              input: "IP address", placeholder: "8.8.8.8") { input, _ in
            let ip = input.trimmed()
            guard IPv4.isIP(ip) else { throw ReconError.invalidInput("enter an IPv4 or IPv6 address") }
            let names = await DNSClient.reverse(ip)
            return single("PTR – \(ip)", names.isEmpty ? [ReportItem("Result", "no PTR record", .low)] : names.map { ReportItem("PTR", $0) })
        })
        tools.append(ToolSpec("email-sec", "Email & DNS Security", "SPF, DKIM, DMARC, MTA-STS, CAA, DNSSEC", icon: "envelope.badge.shield.half.filled", .dns) { input, _ in
            await EmailSecurity.analyze(try domain(input))
        })
        tools.append(ToolSpec("subdomain-brute", "Subdomain Brute-force", "~\(Wordlist.subdomains.count) names, wildcard-aware, via DoH", icon: "text.magnifyingglass", .dns) { input, ctx in
            let d = try domain(input)
            let hits = await Subdomains.bruteForce(domain: d, ctx: ctx)
            var out = ToolOutput(sections: [Subdomains.section(hits, title: "Brute-forced subdomains")])
            out.findings = await Subdomains.takeoverCandidates(hits)
            return out
        })

        // MARK: OSINT
        tools.append(ToolSpec("whois-domain", "WHOIS / RDAP – Domain", "Registrar, dates, nameservers, status", icon: "doc.text.magnifyingglass", .osint) { input, _ in
            try await RDAP.domain(try domain(input))
        })
        tools.append(ToolSpec("whois-ip", "WHOIS / RDAP – IP", "Network allocation, owner, CIDR", icon: "building.2", .osint,
                              input: "IP address", placeholder: "1.1.1.1") { input, _ in
            let ip = input.trimmed()
            guard IPv4.isIP(ip) else { throw ReconError.invalidInput("enter an IP address") }
            return try await RDAP.ip(ip)
        })
        tools.append(ToolSpec("ip-intel", "IP Intelligence", "Geo, ASN, rDNS, Shodan InternetDB (ports, CVEs)", icon: "mappin.and.ellipse", .osint,
                              input: "IP or hostname", placeholder: "8.8.8.8 or example.com") { input, _ in
            let t = try hostOrIP(input)
            let ips = IPv4.isIP(t) ? [t] : await DNSClient.resolveIPs(t)
            guard !ips.isEmpty else { throw ReconError.network("\(t) did not resolve") }
            var out = ToolOutput()
            for ip in ips.prefix(5) { out.merge(await IPIntel.profile(ip)) }
            return out
        })
        tools.append(ToolSpec("ct-logs", "Certificate Transparency", "Subdomains from public CT logs (crt.sh)", icon: "doc.badge.gearshape", .osint) { input, ctx in
            try await CertTransparency.run(try domain(input), ctx: ctx)
        })
        tools.append(ToolSpec("wayback", "Wayback Machine Mining", "Historic URLs, hosts, backups & admin paths", icon: "clock.arrow.circlepath", .osint) { input, _ in
            try await Wayback.run(try domain(input))
        })
        tools.append(ToolSpec("reverse-ip", "Reverse IP Lookup", "Other domains hosted on the same address", icon: "square.stack.3d.up", .osint,
                              input: "IP address", placeholder: "93.184.216.34") { input, _ in
            try await ReverseIP.run(input.trimmed())
        })
        tools.append(ToolSpec("username", "Username Search", "Handle registered on ~\(UsernameSearch.sites.count) platforms", icon: "person.crop.circle.badge.questionmark", .osint,
                              input: "Username", placeholder: "johndoe") { input, ctx in
            try await UsernameSearch.run(input, ctx: ctx)
        })
        tools.append(ToolSpec("email-osint", "Email OSINT", "MX, Gravatar, EmailRep reputation, breaches", icon: "envelope.open", .osint,
                              input: "Email address", placeholder: "name@example.com") { input, ctx in
            try await EmailOSINT.run(input, ctx: ctx)
        })
        tools.append(ToolSpec("github", "GitHub Profile OSINT", "Profile, repos, emails leaked in commits", icon: "chevron.left.forwardslash.chevron.right", .osint,
                              input: "GitHub username", placeholder: "torvalds") { input, ctx in
            try await GitHubOSINT.run(input, ctx: ctx)
        })
        tools.append(ToolSpec("pwned-password", "Password Breach Check", "k-anonymity check against 800M+ leaked passwords", icon: "key.viewfinder", .osint,
                              input: "Password", placeholder: "••••••••", secure: true) { input, _ in
            try await KeyedServices.pwnedPassword(input)
        })
        tools.append(ToolSpec("shodan", "Shodan Host", "Full Shodan record (needs API key in Settings)", icon: "sensor.tag.radiowaves.forward", .osint,
                              input: "IP address", placeholder: "8.8.8.8", key: "shodan") { input, ctx in
            guard let key = ctx.secrets.secret("shodan") else { throw ReconError.unsupported("Add a Shodan API key in Settings first.") }
            return await KeyedServices.shodanHost(input.trimmed(), key: key)
        })
        tools.append(ToolSpec("virustotal", "VirusTotal Reputation", "Domain / IP detections (needs API key in Settings)", icon: "shield.lefthalf.filled.badge.checkmark", .osint,
                              input: "Domain or IP", placeholder: "example.com", key: "virustotal") { input, ctx in
            guard let key = ctx.secrets.secret("virustotal") else { throw ReconError.unsupported("Add a VirusTotal API key in Settings first.") }
            return await KeyedServices.virusTotal(try hostOrIP(input), key: key)
        })

        // MARK: Web
        tools.append(ToolSpec("web-analyze", "HTTP Security Analyzer", "Headers grade, cookies, redirects, tech stack", icon: "checkmark.shield", .web,
                              input: "URL or domain", placeholder: "https://example.com", active: true) { input, _ in
            try await WebRecon.analyze(input)
        })
        tools.append(ToolSpec("content-discovery", "Exposed Files & Paths", "\(ContentDiscovery.probes.count) checks: .git, .env, backups, consoles", icon: "folder.badge.questionmark", .web,
                              input: "URL or domain", placeholder: "https://example.com", active: true) { input, ctx in
            guard let url = WebRecon.normalizeURL(input) else { throw ReconError.invalidInput("bad URL") }
            return await ContentDiscovery.output(base: url, ctx: ctx)
        })
        tools.append(ToolSpec("cors", "CORS Misconfiguration", "Reflected-origin / credentialed wildcard test", icon: "arrow.triangle.branch", .web,
                              input: "URL", placeholder: "https://api.example.com", active: true) { input, _ in
            try await CORSCheck.run(input)
        })
        #if canImport(Network)
        tools.append(ToolSpec("tls", "TLS / Certificate Inspector", "Chain, expiry, SANs, protocol & cipher support", icon: "lock.doc", .web,
                              input: "host[:port]", placeholder: "example.com:443", active: true) { input, _ in
            let raw = input.trimmed()
            var host = TargetParser.stripToHost(raw).lowercased()
            var port: UInt16 = 443
            if !raw.contains("://"), raw.filter({ $0 == ":" }).count == 1, let c = raw.lastIndex(of: ":"), let p = UInt16(raw[raw.index(after: c)...]) {
                port = p; host = String(raw[..<c]).lowercased()
            }
            guard !host.isEmpty else { throw ReconError.invalidInput("enter host[:port]") }
            return TLSAnalysis.output(try await TLSInspector.inspect(host: host, port: port))
        })
        #endif

        // MARK: Network
        #if canImport(Darwin)
        tools.append(ToolSpec("ping", "ICMP Ping", "Real ICMP echo with RTT & TTL", icon: "dot.radiowaves.left.and.right", .network,
                              input: "Host or IP", placeholder: "1.1.1.1", active: true) { input, ctx in
            let h = try hostOrIP(input)
            let replies = await ICMP.ping(host: h, count: 5, progress: { r in
                ctx.log(r.rttMs.map { String(format: "reply from %@: %.1f ms", r.from ?? "?", $0) } ?? "seq \(r.seq): \(r.error ?? "no reply")")
            })
            var s = ReportSection("Ping \(h)")
            for r in replies {
                if let rtt = r.rttMs { s.add("seq \(r.seq)", String(format: "%@  ttl=%d  %.1f ms", r.from ?? "?", r.ttl ?? 0, rtt)) }
                else { s.add("seq \(r.seq)", r.error ?? "no reply", .low) }
            }
            let rtts = replies.compactMap(\.rttMs)
            var stats = ReportSection("Statistics")
            stats.add("Sent / received", "\(replies.count) / \(rtts.count)")
            let loss = replies.isEmpty ? 100 : 100 - Int(Double(rtts.count) / Double(replies.count) * 100)
            stats.add("Packet loss", "\(loss)%", loss == 100 ? .high : (loss > 0 ? .low : .info))
            if let mn = rtts.min(), let mx = rtts.max() {
                stats.add("RTT min / avg / max", String(format: "%.1f / %.1f / %.1f ms", mn, rtts.reduce(0, +) / Double(rtts.count), mx))
            }
            return ToolOutput(sections: [s, stats])
        })
        tools.append(ToolSpec("traceroute", "Traceroute", "ICMP TTL-stepping path discovery", icon: "arrow.triangle.swap", .network,
                              input: "Host or IP", placeholder: "example.com", active: true) { input, ctx in
            let h = try hostOrIP(input)
            let hops = await ICMP.traceroute(host: h, progress: { hop in
                ctx.log(hop.address.map { "\(hop.ttl)  \($0)" } ?? "\(hop.ttl)  *")
            })
            let names = await boundedMap(hops.compactMap(\.address), limit: 6) { ($0, await DNSClient.reverse($0).first) }
            let rdns = Dictionary(names, uniquingKeysWith: { a, _ in a })
            var s = ReportSection("Route to \(h)", note: "Best-effort: some routers do not return ICMP Time Exceeded.")
            for hop in hops {
                if let a = hop.address {
                    let name = rdns[a] ?? nil
                    s.add("\(hop.ttl)", a + (name.map { "  (\($0))" } ?? "") + (hop.rttMs.map { String(format: "   %.1f ms", $0) } ?? ""))
                } else { s.add("\(hop.ttl)", "*  no response", .low) }
            }
            if hops.isEmpty { s.add("Result", "could not resolve or send", .high) }
            return ToolOutput(sections: [s])
        })
        #endif
        tools.append(ToolSpec("subnet", "Subnet Calculator", "Network, mask, broadcast, host range", icon: "square.grid.3x3", .network,
                              input: "CIDR", placeholder: "192.168.1.0/24") { input, _ in
            guard let net = Subnet(cidr: input.trimmed()) else { throw ReconError.invalidInput("use CIDR notation, e.g. 10.0.0.0/22") }
            return ToolOutput(sections: [net.summary()])
        })
        tools.append(ToolSpec("my-ip", "My Public IP", "Your egress address, ISP & location", icon: "location.viewfinder", .network,
                              input: "", placeholder: "tap Run", optional: true) { _, _ in
            let g = try await IPIntel.myIP()
            var s = ReportSection("Your public identity")
            s.add("Public IP", g.ip)
            s.add("Location", [g.city, g.region, g.country].compactMap { $0 }.joined(separator: ", "))
            if let a = g.asn { s.add("ASN", a) }
            if let o = g.org { s.add("Organisation", o) }
            if let i = g.isp { s.add("ISP", i) }
            return ToolOutput(sections: [s])
        })

        // MARK: Utilities
        tools.append(ToolSpec("hash-id", "Hash Identifier", "Recognise MD5/SHA/bcrypt/NTLM… with hashcat modes", icon: "number", .utility,
                              input: "Hash", placeholder: "5f4dcc3b5aa765d61d8327deb882cf99", multiline: true) { input, _ in
            ToolOutput(sections: [HashIdentifier.identify(input)])
        })
        tools.append(ToolSpec("hash-gen", "Hash Generator", "MD5, SHA-1/256/384/512 of any text", icon: "function", .utility,
                              input: "Text", placeholder: "text to hash", multiline: true) { input, _ in
            ToolOutput(sections: [HashIdentifier.generate(input)])
        })
        tools.append(ToolSpec("decode", "Smart Decoder", "Base64, hex, URL, ROT13 in one go", icon: "textformat.abc.dottedunderline", .utility,
                              input: "Text", placeholder: "SGVsbG8=", multiline: true) { input, _ in
            ToolOutput(sections: [Encoders.decodeAll(input)])
        })
        tools.append(ToolSpec("jwt", "JWT Analyzer", "Decode claims, spot alg=none & weak setups", icon: "ticket", .utility,
                              input: "Token", placeholder: "eyJhbGciOi…", multiline: true) { input, _ in
            JWT.analyze(input)
        })
        return tools
    }

    public static func tools(in category: ToolCategory) -> [ToolSpec] { all.filter { $0.category == category } }
}
