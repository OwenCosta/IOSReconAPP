import Foundation

public struct FullReconOptions: Sendable {
    public var dnsAndEmail = true
    public var whois = true
    public var ipIntel = true
    public var certTransparency = true
    public var subdomainBrute = false
    public var wayback = true
    public var webChecks = true
    public var contentDiscovery = true
    public var tls = true
    public var portScan = true
    public var ports: [UInt16] = ServiceDB.top100

    public init() {}
}

public enum ReconEvent: Sendable {
    case stage(name: String, fraction: Double)
    case log(String)
    case section(ReportSection)
    case finding(Finding)
    case finished(ReconReport)
}

/// Runs the whole recon pipeline for a domain or IP and streams progress.
public enum FullRecon {

    public static func run(target rawTarget: String, options: FullReconOptions = FullReconOptions(),
                           secrets: SecretsProvider = NoSecrets()) -> AsyncStream<ReconEvent> {
        AsyncStream { cont in
            let task = Task {
                await execute(rawTarget, options, secrets, cont)
                cont.finish()
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }

    private static func execute(_ rawTarget: String, _ o: FullReconOptions, _ secrets: SecretsProvider,
                                _ cont: AsyncStream<ReconEvent>.Continuation) async {
        let target = TargetParser.stripToHost(rawTarget).lowercased()
        var report = ReconReport(kind: "Full Recon", target: target, project: target)
        let ctx = ToolContext(secrets: secrets, log: { cont.yield(.log($0)) })

        guard IPv4.isIP(target) || TargetParser.domain(from: target) != nil else {
            cont.yield(.log("'\(rawTarget)' is not a valid domain or IP address."))
            report.finished = Date()
            cont.yield(.finished(report))
            return
        }
        let isIP = IPv4.isIP(target)

        func absorb(_ out: ToolOutput) {
            report.sections += out.sections
            report.findings += out.findings
            out.sections.forEach { cont.yield(.section($0)) }
            out.findings.forEach { cont.yield(.finding($0)) }
        }
        func stage(_ name: String, _ frac: Double) {
            cont.yield(.stage(name: name, fraction: frac))
            cont.yield(.log("▶ \(name)"))
        }
        func fail(_ what: String, _ e: Error) {
            cont.yield(.log("✗ \(what): \(e.localizedDescription)"))
        }

        var ips: [String] = isIP ? [target] : []

        // 1. DNS ----------------------------------------------------------------------------
        if !isIP && o.dnsAndEmail {
            stage("DNS records", 0.04)
            let recs = await DNSClient.allRecords(target)
            var s = ReportSection("DNS records (\(recs.count))")
            for r in recs.sorted(by: { ($0.type, $0.data) < ($1.type, $1.data) }) { s.add(r.type, r.data) }
            absorb(ToolOutput(sections: [s]))
            ips = recs.filter { $0.type == "A" || $0.type == "AAAA" }.map(\.data)
            if ips.isEmpty { ips = await DNSClient.resolveIPs(target) }
            ips = Array(NSOrderedSet(array: ips)) as? [String] ?? ips
            if ips.isEmpty { absorb(ToolOutput(findings: [Finding(.info, "\(target) does not resolve", "No A/AAAA records", source: "dns")])) }

            stage("Email & DNS posture", 0.10)
            absorb(await EmailSecurity.analyze(target))
        } else if !isIP {
            ips = await DNSClient.resolveIPs(target)
        }
        if Task.isCancelled { return }

        // 2. Registration -----------------------------------------------------------------
        if o.whois {
            stage("Registration (RDAP)", 0.16)
            do { absorb(isIP ? try await RDAP.ip(target) : try await RDAP.domain(target)) }
            catch { fail("RDAP", error) }
        }

        // 3. IP intelligence ---------------------------------------------------------------
        if o.ipIntel {
            stage("IP intelligence", 0.22)
            for ip in ips.prefix(4) {
                absorb(await IPIntel.profile(ip))
                if let key = secrets.secret("shodan") { absorb(await KeyedServices.shodanHost(ip, key: key)) }
            }
            if let key = secrets.secret("virustotal") { absorb(await KeyedServices.virusTotal(target, key: key)) }
        }
        if Task.isCancelled { return }

        // 4. Subdomains --------------------------------------------------------------------
        if !isIP && (o.certTransparency || o.subdomainBrute || o.wayback) {
            stage("Subdomain enumeration", 0.30)
            var names = Set<String>()
            if o.certTransparency {
                // Multi-source passive enumeration (crt.sh, CertSpotter, HackerTarget, Anubis, OTX, RapidDNS, Wayback).
                let (passive, perSource) = await SubdomainSources.enumerate(domain: target, ctx: ctx)
                names.formUnion(passive)
                var src = ReportSection("Subdomain sources")
                for (n, c) in perSource { src.add(n, "\(c) names") }
                src.add("Total unique", "\(names.count)")
                absorb(ToolOutput(sections: [src]))
            }
            if o.wayback, let urls = try? await Wayback.urls(for: target, limit: 2000) {
                for u in urls { if let h = URL(string: u)?.host?.lowercased(), h.hasSuffix(target) { names.insert(h) } }
            }
            var hits: [SubdomainHit] = []
            if !names.isEmpty {
                cont.yield(.log("Resolving \(min(names.count, 800)) discovered hostnames…"))
                hits = await Subdomains.resolve(Array(names.sorted().prefix(800)), source: "passive")
            }
            if o.subdomainBrute {
                cont.yield(.log("Brute-forcing \(Wordlist.subdomains.count) common subdomain names…"))
                let brute = await Subdomains.bruteForce(domain: target, ctx: ctx)
                let known = Set(hits.map(\.name))
                hits += brute.filter { !known.contains($0.name) }
            }
            if !hits.isEmpty {
                absorb(ToolOutput(sections: [Subdomains.section(hits.sorted { $0.name < $1.name })]))
                absorb(ToolOutput(findings: await Subdomains.takeoverCandidates(hits)))
                let extra = Set(hits.flatMap(\.ips)).subtracting(ips)
                if !extra.isEmpty {
                    var s = ReportSection("Infrastructure footprint")
                    s.add("Distinct IPs across subdomains", "\(Set(hits.flatMap(\.ips)).count)")
                    s.add("Additional IPs (not on apex)", extra.sorted().prefix(30).joined(separator: "\n"))
                    absorb(ToolOutput(sections: [s]))
                }
            } else {
                cont.yield(.log("No subdomains discovered passively."))
            }
        }
        if Task.isCancelled { return }

        // 5. Web ---------------------------------------------------------------------------
        if o.webChecks {
            stage("Web application recon", 0.52)
            do {
                let probe = try await WebRecon.fetchAuto(target)
                absorb(try await WebRecon.analyze(probe.finalURL.absoluteString))
                if o.contentDiscovery { absorb(await ContentDiscovery.output(base: probe.finalURL, ctx: ctx)) }
                absorb(try await CORSCheck.run(probe.finalURL.absoluteString))
                absorb(await SecretScanner.scanWeb(probe.finalURL))
            } catch { fail("Web probe", error) }
        }
        if Task.isCancelled { return }

        // 6. TLS ---------------------------------------------------------------------------
        #if canImport(Network)
        if o.tls {
            stage("TLS inspection", 0.66)
            do { absorb(TLSAnalysis.output(try await TLSInspector.inspect(host: target))) }
            catch { fail("TLS", error) }
        }

        // 7. Ports -------------------------------------------------------------------------
        if o.portScan {
            let scanIPs = Array(ips.filter { IPv4.isIPv4($0) }.prefix(3))
            if scanIPs.isEmpty {
                cont.yield(.log("Skipping port scan: no IPv4 address."))
            } else {
                stage("Port scan (\(o.ports.count) TCP ports × \(scanIPs.count) host\(scanIPs.count == 1 ? "" : "s"))", 0.74)
                var cfg = ScanConfig(targets: scanIPs, ports: o.ports)
                cfg.skipDiscovery = true
                var hostResults: [HostResult] = []
                for await ev in PortScanner().scan(cfg) {
                    switch ev {
                    case .progress(let d, let t): cont.yield(.stage(name: "Port scan \(d)/\(t)", fraction: 0.74 + 0.18 * Double(d) / Double(max(t, 1))))
                    case .finished(let r): hostResults = r
                    default: break
                    }
                }
                for h in hostResults {
                    var s = ReportSection("Open ports – \(h.host)",
                                          note: "\(h.closedCount) closed, \(h.filteredCount) filtered/no-response. TCP connect scan.")
                    if h.likelyProxyInterference {
                        // Don't emit per-port findings we can't trust.
                        s.add("⚠︎ Unreliable", "\(h.openPorts.count)/\(h.scannedCount) ports reported open — a carrier NAT / captive portal / proxy is likely answering for every port. Re-scan on Wi-Fi.", .high)
                        report.findings.append(Finding(.medium, "Port scan of \(h.host) unreliable (proxy/NAT interference)", "Nearly every probed port reported open.", source: "portscan"))
                        cont.yield(.finding(report.findings.last!))
                    } else {
                        for p in h.openPorts {
                            let risk = ServiceDB.risk(port: p.port)
                            var v = p.service
                            if let ver = p.version { v += "  \(ver)" }
                            if let b = p.banner, p.version == nil { v += "  “\(b.prefix(80))”" }
                            s.add("\(p.port)/tcp", v, risk?.severity ?? .info)
                            if let r = risk, r.severity >= .medium {
                                report.findings.append(Finding(r.severity, "Open \(p.service) (\(p.port)/tcp) on \(h.host)", r.why, source: "portscan"))
                                cont.yield(.finding(report.findings.last!))
                            }
                        }
                        if h.openPorts.isEmpty { s.add("Result", "no open ports among scanned set") }
                        if let hint = h.deviceHint { s.add("Role hint", hint) }
                    }
                    report.sections.append(s)
                    cont.yield(.section(s))
                }
            }
        }
        #endif

        // 8. Wayback -----------------------------------------------------------------------
        if !isIP && o.wayback {
            stage("Web archive mining", 0.94)
            do { absorb(try await Wayback.run(target)) } catch { fail("Wayback", error) }
        }

        // Summary -------------------------------------------------------------------------
        report.finished = Date()
        let summary = summarize(report)
        report.sections.insert(summary, at: 0)
        cont.yield(.stage(name: "Done", fraction: 1))
        cont.yield(.finished(report))
    }

    public static func summarize(_ report: ReconReport) -> ReportSection {
        var s = ReportSection("Executive summary – \(report.target)")
        var counts: [Severity: Int] = [:]
        for f in report.findings { counts[f.severity, default: 0] += 1 }
        let weights: [Severity: Int] = [.critical: 25, .high: 12, .medium: 5, .low: 1, .info: 0]
        let score = counts.reduce(0) { $0 + $1.value * (weights[$1.key] ?? 0) }
        let risk: String
        switch score {
        case 0: risk = "No notable issues"
        case 1..<10: risk = "Low"
        case 10..<30: risk = "Moderate"
        case 30..<70: risk = "High"
        default: risk = "Critical"
        }
        s.add("Overall exposure", "\(risk) (score \(score))", score >= 30 ? .high : (score >= 10 ? .medium : .info))
        for sev in Severity.allCases.reversed() where sev != .info {
            s.add(sev.rawValue.capitalized, "\(counts[sev] ?? 0)", (counts[sev] ?? 0) > 0 ? sev : .info)
        }
        if let started = report.finished?.timeIntervalSince(report.started) { s.add("Duration", String(format: "%.0f s", started)) }
        return s
    }
}
