#if canImport(Darwin)
import Foundation
import Darwin

public struct PingReply: Sendable {
    public var seq: Int
    public var from: String?
    public var ttl: Int?
    public var rttMs: Double?
    public var error: String?
}

public struct TraceHop: Sendable {
    public var ttl: Int
    public var address: String?
    public var rttMs: Double?
    public var reachedTarget: Bool
}

/// Real ICMP echo / traceroute using unprivileged datagram ICMP sockets (SOCK_DGRAM + IPPROTO_ICMP),
/// which Darwin allows without root – the same technique Apple's SimplePing sample uses.
public enum ICMP {
    enum EchoResult {
        case reply(from: String, ttl: Int, rtt: Double)
        case timeExceeded(from: String, rtt: Double)
        case unreachable(from: String, rtt: Double)
        case timeout
        case failure(String)
    }

    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < bytes.count { sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1]); i += 2 }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return ~UInt16(sum & 0xFFFF)
    }

    static func makePacket(id: UInt16, seq: UInt16, payload: Int = 32) -> [UInt8] {
        var p: [UInt8] = [8, 0, 0, 0, UInt8(id >> 8), UInt8(id & 0xFF), UInt8(seq >> 8), UInt8(seq & 0xFF)]
        p += (0..<payload).map { UInt8(truncatingIfNeeded: $0 &+ 0x20) }
        let c = checksum(p)
        p[2] = UInt8(c >> 8); p[3] = UInt8(c & 0xFF)
        return p
    }

    static func resolveIPv4(_ host: String) -> sockaddr_in? {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }
        guard let sa = first.pointee.ai_addr else { return nil }
        return sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
    }

    static func ipString(_ a: in_addr) -> String {
        var addr = a
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buf)
    }

    /// One blocking echo probe. Run off the cooperative thread pool.
    static func echo(to dest: sockaddr_in, seq: UInt16, ttl: Int32?, timeout: TimeInterval) -> EchoResult {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return .failure("socket(): \(String(cString: strerror(errno)))") }
        defer { close(fd) }

        if var t = ttl { setsockopt(fd, IPPROTO_IP, IP_TTL, &t, socklen_t(MemoryLayout<Int32>.size)) }

        let packet = makePacket(id: UInt16.random(in: 1...UInt16.max), seq: seq)
        var addr = dest
        let started = DispatchTime.now()
        let sent = packet.withUnsafeBytes { buf -> Int in
            withUnsafePointer(to: &addr) { ap in
                ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, buf.baseAddress, buf.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent > 0 else { return .failure("sendto(): \(String(cString: strerror(errno)))") }

        let deadline = Date().addingTimeInterval(timeout)
        var buf = [UInt8](repeating: 0, count: 1500)
        while true {
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { return .timeout }
            var tv = timeval(tv_sec: Int(remaining), tv_usec: __darwin_suseconds_t((remaining - remaining.rounded(.down)) * 1_000_000))
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            var from = sockaddr_in()
            var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = buf.withUnsafeMutableBytes { raw -> Int in
                withUnsafeMutablePointer(to: &from) { fp in
                    fp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        recvfrom(fd, raw.baseAddress, raw.count, 0, sa, &fromLen)
                    }
                }
            }
            if n < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { return .timeout }
                return .failure("recvfrom(): \(String(cString: strerror(errno)))")
            }
            let rtt = Double(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1_000_000
            let src = ipString(from.sin_addr)

            // Darwin hands us the IP header too; tolerate stacks that don't.
            var off = 0
            var ipTTL = 0
            if n > 20, buf[0] >> 4 == 4 { off = Int(buf[0] & 0x0F) * 4; ipTTL = Int(buf[8]) }
            guard n >= off + 8 else { continue }
            let type = buf[off]
            switch type {
            case 0:
                let rseq = UInt16(buf[off + 6]) << 8 | UInt16(buf[off + 7])
                if rseq == seq { return .reply(from: src, ttl: ipTTL, rtt: rtt) }
            case 11, 3:
                // Payload = original IP header + first 8 bytes of our echo request.
                let inner = off + 8
                guard n > inner + 20, buf[inner] >> 4 == 4 else { continue }
                let innerIHL = Int(buf[inner] & 0x0F) * 4
                let icmp = inner + innerIHL
                guard n >= icmp + 8 else { continue }
                let rseq = UInt16(buf[icmp + 6]) << 8 | UInt16(buf[icmp + 7])
                if rseq == seq { return type == 11 ? .timeExceeded(from: src, rtt: rtt) : .unreachable(from: src, rtt: rtt) }
            default: break
            }
        }
    }

    static func background<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async { cont.resume(returning: work()) }
        }
    }

    // MARK: Public API

    /// Single echo; used by host discovery. Returns the reply source if the host answered.
    public static func isAlive(_ host: String, timeout: TimeInterval = 1.0) async -> Bool {
        guard let dest = resolveIPv4(host) else { return false }
        let r = await background { echo(to: dest, seq: 1, ttl: nil, timeout: timeout) }
        if case .reply = r { return true }
        return false
    }

    public static func ping(host: String, count: Int = 5, interval: TimeInterval = 0.8, timeout: TimeInterval = 2.0,
                            progress: @escaping @Sendable (PingReply) -> Void = { _ in }) async -> [PingReply] {
        guard let dest = resolveIPv4(host) else {
            return [PingReply(seq: 0, from: nil, ttl: nil, rttMs: nil, error: "could not resolve \(host) to an IPv4 address")]
        }
        var out: [PingReply] = []
        for i in 0..<max(1, count) {
            if Task.isCancelled { break }
            let seq = UInt16(i + 1)
            let r = await background { echo(to: dest, seq: seq, ttl: nil, timeout: timeout) }
            let reply: PingReply
            switch r {
            case .reply(let from, let ttl, let rtt): reply = PingReply(seq: i + 1, from: from, ttl: ttl, rttMs: rtt, error: nil)
            case .timeExceeded(let from, _): reply = PingReply(seq: i + 1, from: from, ttl: nil, rttMs: nil, error: "TTL exceeded")
            case .unreachable(let from, _): reply = PingReply(seq: i + 1, from: from, ttl: nil, rttMs: nil, error: "destination unreachable")
            case .timeout: reply = PingReply(seq: i + 1, from: nil, ttl: nil, rttMs: nil, error: "request timed out")
            case .failure(let m): reply = PingReply(seq: i + 1, from: nil, ttl: nil, rttMs: nil, error: m)
            }
            out.append(reply)
            progress(reply)
            if i < count - 1 { try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000)) }
        }
        return out
    }

    public static func traceroute(host: String, maxHops: Int = 30, timeout: TimeInterval = 1.5,
                                  progress: @escaping @Sendable (TraceHop) -> Void = { _ in }) async -> [TraceHop] {
        guard let dest = resolveIPv4(host) else { return [] }
        var hops: [TraceHop] = []
        var silent = 0
        for ttl in 1...max(1, maxHops) {
            if Task.isCancelled { break }
            let r = await background { echo(to: dest, seq: UInt16(ttl), ttl: Int32(ttl), timeout: timeout) }
            let hop: TraceHop
            switch r {
            case .reply(let from, _, let rtt): hop = TraceHop(ttl: ttl, address: from, rttMs: rtt, reachedTarget: true)
            case .timeExceeded(let from, let rtt): hop = TraceHop(ttl: ttl, address: from, rttMs: rtt, reachedTarget: false)
            case .unreachable(let from, let rtt): hop = TraceHop(ttl: ttl, address: from, rttMs: rtt, reachedTarget: true)
            default: hop = TraceHop(ttl: ttl, address: nil, rttMs: nil, reachedTarget: false)
            }
            hops.append(hop)
            progress(hop)
            silent = hop.address == nil ? silent + 1 : 0
            if hop.reachedTarget || silent >= 6 { break }
        }
        return hops
    }
}
#endif
