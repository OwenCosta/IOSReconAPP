import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Wire format (used by UDP probes)

public enum DNSWire {
    public static func query(name: String, type: UInt16, qclass: UInt16 = 1, id: UInt16 = 0x5EC0) -> Data {
        var b: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8.prefix(63))
            b.append(UInt8(bytes.count))
            b += bytes
        }
        b += [0x00, UInt8(type >> 8), UInt8(type & 0xFF), UInt8(qclass >> 8), UInt8(qclass & 0xFF)]
        return Data(b)
    }
}

// MARK: - Types

public enum DNSType: String, CaseIterable, Sendable {
    case A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV, PTR, DS, DNSKEY

    public var code: Int {
        switch self {
        case .A: return 1
        case .NS: return 2
        case .CNAME: return 5
        case .SOA: return 6
        case .PTR: return 12
        case .MX: return 15
        case .TXT: return 16
        case .AAAA: return 28
        case .SRV: return 33
        case .DS: return 43
        case .DNSKEY: return 48
        case .CAA: return 257
        }
    }

    static func name(for code: Int) -> String {
        allCases.first { $0.code == code }?.rawValue ?? "TYPE\(code)"
    }
}

public struct DNSRecord: Codable, Hashable, Identifiable, Sendable {
    public var name: String
    public var type: String
    public var ttl: Int
    public var data: String
    public var id: String { "\(name)|\(type)|\(data)" }
}

public struct DNSAnswer: Sendable {
    public var records: [DNSRecord]
    public var status: Int           // 0 NOERROR, 3 NXDOMAIN, 2 SERVFAIL
    public var authenticated: Bool   // AD bit (DNSSEC validated)
    public var exists: Bool { status == 0 }
}

public enum DNSResolver: String, Sendable {
    case cloudflare = "https://cloudflare-dns.com/dns-query"
    case google = "https://dns.google/resolve"
}

// MARK: - DNS-over-HTTPS client

public enum DNSClient {
    public static func query(_ name: String, type: DNSType, resolver: DNSResolver = .cloudflare,
                             dnssec: Bool = false) async throws -> DNSAnswer {
        var comps = URLComponents(string: resolver.rawValue)!
        comps.queryItems = [URLQueryItem(name: "name", value: name),
                            URLQueryItem(name: "type", value: type.rawValue)]
        if dnssec { comps.queryItems?.append(URLQueryItem(name: "do", value: "1")) }
        guard let url = comps.url else { throw ReconError.invalidInput("bad DNS name \(name)") }

        var lastError: Error = ReconError.network("DNS query failed")
        for attempt in 0..<2 {
            do {
                let raw = try await HTTP.json(url, headers: ["Accept": "application/dns-json"], timeout: 8)
                guard let obj = raw as? [String: Any] else { throw ReconError.parse("DNS response") }
                let recs = obj.dicts("Answer").compactMap { a -> DNSRecord? in
                    guard let t = a.int("type"), let data = a.str("data") else { return nil }
                    var d = data
                    if t == DNSType.TXT.code { d = unquoteTXT(d) }
                    if t == DNSType.CNAME.code || t == DNSType.NS.code || t == DNSType.PTR.code
                        || t == DNSType.MX.code { d = d.hasSuffix(".") ? String(d.dropLast()) : d }
                    var n = a.str("name") ?? name
                    if n.hasSuffix(".") { n.removeLast() }
                    return DNSRecord(name: n, type: DNSType.name(for: t), ttl: a.int("TTL") ?? 0, data: d)
                }
                return DNSAnswer(records: recs, status: obj.int("Status") ?? 0, authenticated: (obj["AD"] as? Bool) ?? false)
            } catch {
                lastError = error
                if attempt == 0 { try? await Task.sleep(nanoseconds: 300_000_000) }
            }
        }
        throw lastError
    }

    /// `"part one" "part two"` → `part onepart two`
    static func unquoteTXT(_ s: String) -> String {
        var t = s
        if t.hasPrefix("\"") && t.hasSuffix("\"") && t.count >= 2 { t = String(t.dropFirst().dropLast()) }
        return t.replacingOccurrences(of: "\" \"", with: "").replacingOccurrences(of: "\\\"", with: "\"")
    }

    /// Records of one type, ignoring errors (empty array on failure).
    public static func records(_ name: String, _ type: DNSType) async -> [DNSRecord] {
        ((try? await query(name, type: type))?.records ?? []).filter { $0.type == type.rawValue }
    }

    /// Resolve A + AAAA, following CNAME chains returned by the resolver.
    public static func resolveIPs(_ name: String) async -> [String] {
        async let a = records(name, .A)
        async let aaaa = records(name, .AAAA)
        let all = await a + aaaa
        var seen = Set<String>()
        return all.map(\.data).filter { seen.insert($0).inserted }
    }

    public static func reverse(_ ip: String) async -> [String] {
        guard let name = reverseName(ip) else { return [] }
        return await records(name, .PTR).map(\.data)
    }

    public static func reverseName(_ ip: String) -> String? {
        if IPv4.parse(ip) != nil {
            return ip.split(separator: ".").reversed().joined(separator: ".") + ".in-addr.arpa"
        }
        guard let nibbles = expandIPv6(ip) else { return nil }
        return nibbles.reversed().map(String.init).joined(separator: ".") + ".ip6.arpa"
    }

    /// 32 hex nibbles for an IPv6 literal, or nil.
    static func expandIPv6(_ addr: String) -> [Character]? {
        var s = addr.split(separator: "%").first.map(String.init) ?? addr
        guard s.contains(":") else { return nil }
        // embedded IPv4 tail
        if let lastColon = s.lastIndex(of: ":"), s[s.index(after: lastColon)...].contains("."),
           let v4 = IPv4.parse(String(s[s.index(after: lastColon)...])) {
            s = String(s[...lastColon]) + String(format: "%x:%x", v4 >> 16, v4 & 0xFFFF)
        }
        let halves = s.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        let head = halves[0].isEmpty ? [] : halves[0].split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        let tail = halves.count == 2 && !halves[1].isEmpty
            ? halves[1].split(separator: ":", omittingEmptySubsequences: false).map(String.init) : []
        var groups = head
        if halves.count == 2 {
            let missing = 8 - head.count - tail.count
            guard missing >= 0 else { return nil }
            groups += [String](repeating: "0", count: missing) + tail
        }
        guard groups.count == 8 else { return nil }
        var out: [Character] = []
        for g in groups {
            guard !g.isEmpty, g.count <= 4, g.allSatisfy({ $0.isHexDigit }) else { return nil }
            out += Array(String(repeating: "0", count: 4 - g.count) + g.lowercased())
        }
        return out
    }

    /// Everything interesting for a domain, grouped by type.
    public static func allRecords(_ domain: String) async -> [DNSRecord] {
        let types: [DNSType] = [.A, .AAAA, .CNAME, .NS, .MX, .TXT, .SOA, .CAA]
        let groups = await boundedMap(types, limit: 8) { await records(domain, $0) }
        var seen = Set<String>()
        return groups.flatMap { $0 }.filter { seen.insert($0.id).inserted }
    }
}
