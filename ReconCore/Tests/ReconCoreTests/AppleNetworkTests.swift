#if canImport(Network)
import XCTest
import Network
@testable import ReconCore

/// Runs on macOS CI (and locally on a Mac): exercises the real Network.framework scanner against loopback.
final class AppleNetworkTests: XCTestCase {

    final class LoopbackServer {
        let listener: NWListener
        private(set) var port: UInt16 = 0
        private let lock = NSLock()
        private var resumed = false

        init(banner: String?) throws {
            listener = try NWListener(using: .tcp, on: .any)
            listener.newConnectionHandler = { conn in
                conn.start(queue: .global())
                if let b = banner { conn.send(content: Data(b.utf8), completion: .contentProcessed { _ in }) }
            }
        }

        func start() async -> UInt16 {
            await withCheckedContinuation { (cont: CheckedContinuation<UInt16, Never>) in
                listener.stateUpdateHandler = { [self] st in
                    if case .ready = st {
                        lock.lock(); defer { lock.unlock() }
                        if !resumed, let p = listener.port { resumed = true; port = p.rawValue; cont.resume(returning: p.rawValue) }
                    }
                }
                listener.start(queue: .global())
            }
        }
        func stop() { listener.cancel() }
    }

    func testDetectsOpenPortAndBanner() async throws {
        let server = try LoopbackServer(banner: "SSH-2.0-OpenSSH_9.6 test\r\n")
        let port = await server.start()
        defer { server.stop() }
        let r = await PortScanner.probeTCP(host: "127.0.0.1", port: port, timeout: 3, banner: true)
        XCTAssertEqual(r.state, .open)
        XCTAssertEqual(r.service, "ssh")
        XCTAssertEqual(r.version, "OpenSSH 9.6 (protocol 2.0)")
    }

    func testDetectsOpenPortWithoutBanner() async throws {
        let server = try LoopbackServer(banner: nil)
        let port = await server.start()
        defer { server.stop() }
        let r = await PortScanner.probeTCP(host: "127.0.0.1", port: port, timeout: 3, banner: false)
        XCTAssertEqual(r.state, .open)
    }

    func testDetectsClosedPort() async throws {
        let server = try LoopbackServer(banner: nil)
        let port = await server.start()
        server.stop()
        try await Task.sleep(nanoseconds: 300_000_000)
        let r = await PortScanner.probeTCP(host: "127.0.0.1", port: port, timeout: 3, banner: false)
        XCTAssertEqual(r.state, .closed, "reason: \(r.reason)")
    }

    func testFullScanPipeline() async throws {
        let a = try LoopbackServer(banner: "220 mail ESMTP Postfix\r\n")
        let pa = await a.start()
        defer { a.stop() }
        var cfg = ScanConfig(targets: ["127.0.0.1"], ports: [pa, 1])
        cfg.timeout = 2
        var finished: [HostResult] = []
        var sawPort = false
        for await ev in PortScanner().scan(cfg) {
            if case .port(let p) = ev, p.port == pa { sawPort = true }
            if case .finished(let h) = ev { finished = h }
        }
        XCTAssertTrue(sawPort)
        XCTAssertEqual(finished.count, 1)
        XCTAssertEqual(finished[0].openPorts.map(\.port), [pa])
        XCTAssertEqual(finished[0].openPorts.first?.service, "smtp")
        XCTAssertGreaterThanOrEqual(finished[0].closedCount + finished[0].filteredCount, 1)
    }

    func testHostDiscoveryFindsLoopback() async {
        let up = await HostDiscovery.isAlive("127.0.0.1")
        XCTAssertNotNil(up)
    }

    func testLocalInterfacesIncludeLoopback() {
        XCTAssertTrue(LocalNetwork.interfaces().contains { $0.address == "127.0.0.1" })
    }

    func testICMPChecksumAndPacket() {
        XCTAssertEqual(ICMP.checksum([8, 0, 0, 0, 0, 0, 0, 0]), 0xF7FF)
        let p = ICMP.makePacket(id: 0x1234, seq: 7)
        XCTAssertEqual(p[0], 8)
        XCTAssertEqual(p[6], 0)
        XCTAssertEqual(p[7], 7)
        XCTAssertEqual(ICMP.checksum(p), 0, "a valid ICMP packet checksums to zero")
    }

    func testICMPPingLoopback() async throws {
        let replies = await ICMP.ping(host: "127.0.0.1", count: 2, interval: 0.1, timeout: 2)
        guard replies.contains(where: { $0.rttMs != nil }) else {
            throw XCTSkip("ICMP datagram sockets unavailable in this environment: \(replies.compactMap(\.error))")
        }
        XCTAssertEqual(replies.first?.from, "127.0.0.1")
    }
}
#endif
