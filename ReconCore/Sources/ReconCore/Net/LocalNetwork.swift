#if canImport(Darwin)
import Foundation
import Darwin

public struct NetInterface: Codable, Identifiable, Hashable, Sendable {
    public var name: String
    public var address: String
    public var netmask: String
    public var family: String
    public var isUp: Bool
    public var id: String { "\(name)-\(address)" }

    public var prefix: Int? {
        guard family == "IPv4", let m = IPv4.parse(netmask) else { return nil }
        return m.nonzeroBitCount
    }
    public var cidr: String? {
        guard let p = prefix, let ip = IPv4.parse(address) else { return nil }
        return Subnet(address: ip, prefix: p).cidr
    }
    public var kind: String {
        if name.hasPrefix("en0") { return "Wi-Fi" }
        if name.hasPrefix("pdp_ip") { return "Cellular" }
        if name.hasPrefix("lo") { return "Loopback" }
        if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("ppp") { return "VPN/Tunnel" }
        if name.hasPrefix("bridge") { return "Hotspot bridge" }
        if name.hasPrefix("awdl") { return "AirDrop (AWDL)" }
        if name.hasPrefix("en") { return "Ethernet/Other" }
        return "Other"
    }
}

public enum LocalNetwork {
    public static func interfaces() -> [NetInterface] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        func numeric(_ sa: UnsafeMutablePointer<sockaddr>) -> String {
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            return String(cString: host)
        }

        var result: [NetInterface] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let p = cursor {
            let ifa = p.pointee
            cursor = ifa.ifa_next
            guard let sa = ifa.ifa_addr else { continue }
            let fam = Int32(sa.pointee.sa_family)
            guard fam == AF_INET || fam == AF_INET6 else { continue }
            let up = Int32(ifa.ifa_flags) & IFF_UP != 0
            let mask = ifa.ifa_netmask.map(numeric) ?? ""
            result.append(NetInterface(name: String(cString: ifa.ifa_name), address: numeric(sa), netmask: mask,
                                       family: fam == AF_INET ? "IPv4" : "IPv6", isUp: up))
        }
        return result
    }

    /// The Wi-Fi (or best private) IPv4 subnet – what "scan my network" should target.
    public static func primarySubnet() -> (interface: NetInterface, subnet: Subnet)? {
        let v4 = interfaces().filter { $0.family == "IPv4" && $0.isUp && !$0.name.hasPrefix("lo") }
        let candidates = v4.sorted { a, b in
            func rank(_ i: NetInterface) -> Int { i.name == "en0" ? 0 : (i.name.hasPrefix("bridge") ? 1 : (i.name.hasPrefix("en") ? 2 : 9)) }
            return rank(a) < rank(b)
        }
        for i in candidates {
            if let ip = IPv4.parse(i.address), IPv4.isPrivate(ip), let p = i.prefix {
                return (i, Subnet(address: ip, prefix: max(p, 20)))   // cap at /20 (4094 hosts)
            }
        }
        return nil
    }

    /// Conventional gateway guess (.1 on the subnet) – iOS exposes no public routing-table API.
    public static func likelyGateway(_ s: Subnet) -> String { IPv4.string(s.network + 1) }
}
#endif
