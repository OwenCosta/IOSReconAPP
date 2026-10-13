#if canImport(Network)
import Foundation
import Network
#if canImport(Darwin)
import Darwin
#endif

// MARK: - Config & events

public struct ScanConfig: Sendable {
    public var targets: [String]
    public var ports: [UInt16]
    public var timeout: TimeInterval = 1.5
    public var concurrency: Int = 120
    public var grabBanners = true
    public var includeUDP = false
    /// -Pn equivalent. Single targets are never pre-filtered by discovery.
    public var skipDiscovery = false
    public var randomizeOrder = true

    public init(targets: [String], ports: [UInt16]) {
        self.targets = targets
        self.ports = ports
    }
}

public enum ScanEvent: Sendable {
    case started(totalProbes: Int, hosts: Int)
    case hostUp(host: String, reason: String)
    case port(PortResult)
    case progress(done: Int, total: Int)
    case finished([HostResult])
}

/// Single-shot latch used to make sure continuations are resumed exactly once.
final class Gate: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    private var flagged = false

    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
    var isClaimed: Bool { lock.lock(); defer { lock.unlock() }; return claimed }
    func setFlag() { lock.lock(); flagged = true; lock.unlock() }
    var flag: Bool { lock.lock(); defer { lock.unlock() }; return flagged }
}

// MARK: - Scanner

/// TCP connect() scanner built on Network.framework (iOS forbids raw sockets, so no SYN scan),
/// plus a handful of UDP service probes.
public final class PortScanner: @unchecked Sendable {
    public init() {}

    public func scan(_ config: ScanConfig) -> AsyncStream<ScanEvent> {
        AsyncStream { cont in
            let task = Task { [self] in
                await run(config, cont)
                cont.finish()
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }

    private func run(_ c: ScanConfig, _ cont: AsyncStream<ScanEvent>.Continuation) async {
        Self.raiseFileLimit()

        // Phase 1: host discovery (multi-host scans only)
        var hosts = c.targets.map { ($0, "user-specified") }
        if c.targets.count > 1 && !c.skipDiscovery {
            hosts = await HostDiscovery.sweep(c.targets, onUp: { h, why in cont.yield(.hostUp(host: h, reason: why)) })
        }
        guard !hosts.isEmpty, !Task.isCancelled else {
            cont.yield(.finished([]))
            return
        }

        // Phase 2: port probes
        var jobs: [(String, UInt16, Bool)] = []
        for (h, _) in hosts {
            for p in c.ports { jobs.append((h, p, false)) }
            if c.includeUDP { for p in UDPProbe.ports { jobs.append((h, p, true)) } }
        }
        if c.randomizeOrder { jobs.shuffle() }
        let total = jobs.count
        cont.yield(.started(totalProbes: total, hosts: hosts.count))

        var open: [String: [PortResult]] = [:]
        var closed: [String: Int] = [:]
        var filtered: [String: Int] = [:]
        var done = 0
        var idx = 0
        let timeout = c.timeout
        let banners = c.grabBanners

        await withTaskGroup(of: PortResult.self) { group in
            func spawn(_ j: (String, UInt16, Bool)) {
                group.addTask {
                    j.2 ? await UDPProbe.probe(host: j.0, port: j.1, timeout: max(timeout, 2.0))
                        : await PortScanner.probeTCP(host: j.0, port: j.1, timeout: timeout, banner: banners)
                }
            }
            while idx < min(c.concurrency, total) { spawn(jobs[idx]); idx += 1 }
            while let r = await group.next() {
                done += 1
                switch r.state {
                case .open:
                    open[r.host, default: []].append(r)
                    cont.yield(.port(r))
                case .openFiltered:
                    if r.proto == "udp" { filtered[r.host, default: 0] += 1 }
                case .closed: closed[r.host, default: 0] += 1
                case .filtered: filtered[r.host, default: 0] += 1
                }
                if done % 20 == 0 || done == total { cont.yield(.progress(done: done, total: total)) }
                if idx < total && !Task.isCancelled { spawn(jobs[idx]); idx += 1 }
            }
        }

        let results = hosts.map { (h, why) -> HostResult in
            let ports = (open[h] ?? []).sorted { ($0.proto, $0.port) < ($1.proto, $1.port) }
            return HostResult(host: h, alive: true, aliveReason: why, openPorts: ports,
                              closedCount: closed[h] ?? 0, filteredCount: filtered[h] ?? 0,
                              deviceHint: ServiceDB.deviceHint(openPorts: Set(ports.filter { $0.proto == "tcp" }.map(\.port))))
        }
        cont.yield(.finished(results))
    }

    static func raiseFileLimit() {
        #if canImport(Darwin)
        var lim = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &lim) == 0 else { return }
        let want: rlim_t = 4096
        if lim.rlim_cur < want {
            lim.rlim_cur = min(want, lim.rlim_max)   // rlim_max may be "infinity" (huge), so min() is enough
            _ = setrlimit(RLIMIT_NOFILE, &lim)
        }
        #endif
    }

    // MARK: TCP probe

    static func classify(_ err: NWError) -> (PortState, String) {
        if case .posix(let code) = err {
            switch code {
            case .ECONNREFUSED: return (.closed, "conn-refused")
            case .ETIMEDOUT: return (.filtered, "timed-out")
            case .EHOSTUNREACH: return (.filtered, "host-unreachable")
            case .ENETUNREACH: return (.filtered, "net-unreachable")
            default: return (.filtered, "posix-\(code.rawValue)")
            }
        }
        return (.filtered, "\(err)")
    }

    /// Performs one TCP connect. `open` = handshake completed; `closed` = RST; `filtered` = silence/ICMP errors.
    public static func probeTCP(host: String, port: UInt16, timeout: TimeInterval, banner: Bool) async -> PortResult {
        let start = Date()
        return await withCheckedContinuation { (cont: CheckedContinuation<PortResult, Never>) in
            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                cont.resume(returning: PortResult(host: host, port: port, state: .filtered, reason: "bad-port"))
                return
            }
            let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
            let gate = Gate()
            let q = DispatchQueue(label: "recon.tcp.\(host).\(port)")

            func finish(_ state: PortState, _ reason: String, banner: String? = nil) {
                guard gate.claim() else { return }
                conn.stateUpdateHandler = nil
                conn.cancel()
                var r = PortResult(host: host, port: port, state: state, reason: reason,
                                   latencyMs: Date().timeIntervalSince(start) * 1000)
                if let b = banner, !b.isEmpty { ServiceFingerprint.apply(banner: b, to: &r) }
                cont.resume(returning: r)
            }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    gate.setFlag()
                    if banner && !ServiceDB.tlsPorts.contains(port) {
                        grabBanner(conn, port: port, queue: q, wait: min(max(timeout, 1.0), 2.5)) { text in
                            finish(.open, "syn-ack", banner: text)
                        }
                    } else {
                        finish(.open, "syn-ack")
                    }
                case .waiting(let err), .failed(let err):
                    let (s, why) = classify(err)
                    finish(s, why)
                default: break
                }
            }
            conn.start(queue: q)
            q.asyncAfter(deadline: .now() + timeout) {
                if !gate.flag { finish(.filtered, "no-response") }
            }
        }
    }

    private static func grabBanner(_ conn: NWConnection, port: UInt16, queue: DispatchQueue,
                                   wait: TimeInterval, completion: @escaping (String?) -> Void) {
        let once = Gate()
        func done(_ s: String?) { if once.claim() { completion(s) } }

        conn.receive(minimumIncompleteLength: 1, maximumLength: 2048) { data, _, _, _ in
            if let d = data, !d.isEmpty { done(ServiceFingerprint.clean(d)) } else { done(nil) }
        }
        // Server-first protocols answer immediately; otherwise nudge it after a short pause.
        queue.asyncAfter(deadline: .now() + 0.6) {
            guard !once.isClaimed, let payload = ServiceFingerprint.probePayload(port: port) else { return }
            conn.send(content: payload, completion: .contentProcessed { _ in })
        }
        queue.asyncAfter(deadline: .now() + wait) { done(nil) }
    }
}

// MARK: - UDP probes

public enum UDPProbe {
    public static let ports: [UInt16] = [53, 123, 137, 161, 1900, 5353]

    static func payload(for port: UInt16) -> Data {
        switch port {
        case 53: return DNSWire.query(name: "version.bind", type: 16, qclass: 3)
        case 123: return Data([0x1B] + [UInt8](repeating: 0, count: 47))
        case 137:
            var b: [UInt8] = [0xA2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20]
            b += Array("CK".utf8) + [UInt8](repeating: 0x41, count: 30) + [0x00, 0x00, 0x21, 0x00, 0x01]
            return Data(b)
        case 161:
            return Data([0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
                         0xA0, 0x1C, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
                         0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
                         0x05, 0x00])
        case 1900:
            return Data("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n".utf8)
        case 5353: return DNSWire.query(name: "_services._dns-sd._udp.local", type: 12)
        default: return Data([0])
        }
    }

    public static func probe(host: String, port: UInt16, timeout: TimeInterval) async -> PortResult {
        let start = Date()
        return await withCheckedContinuation { (cont: CheckedContinuation<PortResult, Never>) in
            guard let p = NWEndpoint.Port(rawValue: port) else {
                cont.resume(returning: PortResult(host: host, port: port, proto: "udp", state: .filtered))
                return
            }
            let conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: .udp)
            let gate = Gate()
            let q = DispatchQueue(label: "recon.udp.\(host).\(port)")

            func finish(_ state: PortState, _ reason: String, data: Data? = nil) {
                guard gate.claim() else { return }
                conn.stateUpdateHandler = nil
                conn.cancel()
                var r = PortResult(host: host, port: port, proto: "udp", state: state, reason: reason,
                                   latencyMs: Date().timeIntervalSince(start) * 1000)
                if let d = data, !d.isEmpty { r.banner = ServiceFingerprint.clean(d, limit: 120) }
                cont.resume(returning: r)
            }

            conn.stateUpdateHandler = { st in
                switch st {
                case .ready:
                    conn.send(content: payload(for: port), completion: .contentProcessed { err in
                        if let err = err { let (s, why) = PortScanner.classify(err); finish(s, why) }
                    })
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, _, err in
                        if let d = data, !d.isEmpty { finish(.open, "udp-response", data: d) }
                        else if let err = err { let (s, why) = PortScanner.classify(err); finish(s, why) }
                    }
                case .failed(let err), .waiting(let err):
                    let (s, why) = PortScanner.classify(err)
                    finish(s, why)
                default: break
                }
            }
            conn.start(queue: q)
            q.asyncAfter(deadline: .now() + timeout) { finish(.openFiltered, "no-response") }
        }
    }
}
#endif
