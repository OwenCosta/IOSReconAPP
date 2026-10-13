import Foundation

// MARK: - IPv4 helpers

public enum IPv4 {
    public static func parse(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var v: UInt32 = 0
        for p in parts {
            guard !p.isEmpty, p.count <= 3, p.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let n = UInt32(p), n <= 255 else { return nil }
            v = (v << 8) | n
        }
        return v
    }

    public static func string(_ v: UInt32) -> String {
        "\((v >> 24) & 255).\((v >> 16) & 255).\((v >> 8) & 255).\(v & 255)"
    }

    public static func isPrivate(_ v: UInt32) -> Bool {
        let a = v >> 24, b = (v >> 16) & 255
        return a == 10 || (a == 172 && (16...31).contains(b)) || (a == 192 && b == 168)
            || (a == 169 && b == 254) || a == 127 || (a == 100 && (64...127).contains(b))
    }

    public static func isIPv4(_ s: String) -> Bool { parse(s) != nil }

    public static func isIPv6(_ s: String) -> Bool {
        let core = s.split(separator: "%").first.map(String.init) ?? s
        return core.contains(":") && core.allSatisfy { $0.isHexDigit || $0 == ":" || $0 == "." }
    }

    public static func isIP(_ s: String) -> Bool { isIPv4(s) || isIPv6(s) }
}

// MARK: - Subnet maths

public struct Subnet: Sendable, Hashable {
    public let network: UInt32
    public let prefix: Int

    public init?(cidr: String) {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let ip = IPv4.parse(String(parts[0])),
              let p = Int(parts[1]), (0...32).contains(p) else { return nil }
        self.prefix = p
        self.network = ip & Subnet.mask(for: p)
    }

    public init(address: UInt32, prefix: Int) {
        self.prefix = prefix
        self.network = address & Subnet.mask(for: prefix)
    }

    static func mask(for prefix: Int) -> UInt32 { prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix) }

    public var mask: UInt32 { Subnet.mask(for: prefix) }
    public var broadcast: UInt32 { network | ~mask }
    public var totalAddresses: UInt64 { 1 << UInt64(32 - prefix) }
    public var usableHosts: UInt64 {
        switch prefix {
        case 32: return 1
        case 31: return 2
        default: return totalAddresses - 2
        }
    }
    public var firstHost: UInt32 { prefix >= 31 ? network : network + 1 }
    public var lastHost: UInt32 { prefix >= 31 ? broadcast : broadcast - 1 }
    public var cidr: String { "\(IPv4.string(network))/\(prefix)" }

    public func hostAddresses() -> [String] {
        var out: [String] = []
        out.reserveCapacity(Int(min(usableHosts, 1 << 20)))
        var a = UInt64(firstHost)
        let end = UInt64(lastHost)
        while a <= end { out.append(IPv4.string(UInt32(a))); a += 1 }
        return out
    }

    public func contains(_ ip: UInt32) -> Bool { (ip & mask) == network }

    public func summary() -> ReportSection {
        var s = ReportSection("Subnet \(cidr)")
        s.add("Network", IPv4.string(network))
        s.add("Netmask", IPv4.string(mask))
        s.add("Wildcard", IPv4.string(~mask))
        s.add("Broadcast", IPv4.string(broadcast))
        s.add("First host", IPv4.string(firstHost))
        s.add("Last host", IPv4.string(lastHost))
        s.add("Usable hosts", "\(usableHosts)")
        s.add("Class / scope", IPv4.isPrivate(network) ? "Private / non-routable" : "Public")
        return s
    }
}

// MARK: - Target expansion

public enum TargetParser {
    /// Accepts hostnames, IPv4, IPv6, URLs, CIDR blocks (10.0.0.0/24) and ranges
    /// (10.0.0.5-20 or 10.0.0.5-10.0.0.40), separated by commas / whitespace.
    public static func expand(_ input: String, maxHosts: Int = 4096) throws -> [String] {
        let tokens = input.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" || $0 == ";" }).map(String.init)
        guard !tokens.isEmpty else { throw ReconError.invalidInput("no target given") }

        var out: [String] = []
        var seen = Set<String>()
        func push(_ h: String) { if seen.insert(h).inserted { out.append(h) } }

        for raw in tokens {
            let token = stripToHost(raw)
            if token.contains("/") {
                guard let net = Subnet(cidr: token) else { throw ReconError.invalidInput("bad CIDR '\(raw)'") }
                guard net.usableHosts <= UInt64(maxHosts) else {
                    throw ReconError.invalidInput("\(net.cidr) has \(net.usableHosts) hosts (limit \(maxHosts)). Use a smaller block.")
                }
                net.hostAddresses().forEach(push)
            } else if let dash = token.firstIndex(of: "-"), IPv4.parse(String(token[..<dash])) != nil {
                let start = IPv4.parse(String(token[..<dash]))!
                let tail = String(token[token.index(after: dash)...])
                let end: UInt32
                if let full = IPv4.parse(tail) { end = full }
                else if let last = UInt32(tail), last <= 255 { end = (start & 0xFFFFFF00) | last }
                else { throw ReconError.invalidInput("bad range '\(raw)'") }
                guard end >= start, UInt64(end - start) < UInt64(maxHosts) else {
                    throw ReconError.invalidInput("range '\(raw)' is empty or larger than \(maxHosts) hosts")
                }
                var a = UInt64(start)
                while a <= UInt64(end) { push(IPv4.string(UInt32(a))); a += 1 }
            } else if IPv4.isIP(token) || isValidHostname(token) {
                push(token.lowercased())
            } else {
                throw ReconError.invalidInput("'\(raw)' is not a valid host, IP or CIDR")
            }
        }
        return out
    }

    /// "https://User@Example.com:8443/path?x" -> "example.com"
    public static func stripToHost(_ raw: String) -> String {
        var s = raw.trimmed()
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        if let slash = s.firstIndex(of: "/"), !isCIDRLike(s) { s = String(s[..<slash]) }
        if let at = s.lastIndex(of: "@") { s = String(s[s.index(after: at)...]) }
        if let q = s.firstIndex(where: { $0 == "?" || $0 == "#" }) { s = String(s[..<q]) }
        // strip :port for hostnames / IPv4 (leave IPv6 alone)
        if s.filter({ $0 == ":" }).count == 1, let c = s.firstIndex(of: ":") { s = String(s[..<c]) }
        while s.hasSuffix(".") { s.removeLast() }
        return s
    }

    private static func isCIDRLike(_ s: String) -> Bool {
        guard let slash = s.firstIndex(of: "/") else { return false }
        return IPv4.parse(String(s[..<slash])) != nil && Int(s[s.index(after: slash)...]) != nil
    }

    public static func isValidHostname(_ h: String) -> Bool {
        guard !h.isEmpty, h.count <= 253 else { return false }
        let labels = h.split(separator: ".", omittingEmptySubsequences: false)
        return labels.allSatisfy { l in
            !l.isEmpty && l.count <= 63 && !l.hasPrefix("-") && !l.hasSuffix("-")
                && l.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
        }
    }

    /// A single registrable-looking domain, lower-cased, or nil.
    public static func domain(from input: String) -> String? {
        let h = stripToHost(input).lowercased()
        guard isValidHostname(h), h.contains("."), !IPv4.isIPv4(h) else { return nil }
        return h
    }
}

// MARK: - Port specifications

public enum PortSpec {
    /// "22,80,8000-8100", "top100", "common", "all", "-"
    public static func parse(_ spec: String) throws -> [UInt16] {
        var set = Set<UInt16>()
        for raw in spec.split(whereSeparator: { $0 == "," || $0 == " " }) {
            let t = raw.lowercased()
            switch t {
            case "top100", "top": set.formUnion(ServiceDB.top100)
            case "common", "top20": set.formUnion(ServiceDB.top20)
            case "all", "-": set.formUnion((1...65535).map { UInt16($0) })
            default:
                if let dash = t.firstIndex(of: "-") {
                    guard let a = Int(t[..<dash]), let b = Int(t[t.index(after: dash)...]),
                          (1...65535).contains(a), (1...65535).contains(b), a <= b else {
                        throw ReconError.invalidInput("bad port range '\(raw)'")
                    }
                    for p in a...b { set.insert(UInt16(p)) }
                } else if let p = Int(t), (1...65535).contains(p) {
                    set.insert(UInt16(p))
                } else {
                    throw ReconError.invalidInput("bad port '\(raw)'")
                }
            }
        }
        guard !set.isEmpty else { throw ReconError.invalidInput("no ports selected") }
        return set.sorted()
    }
}
