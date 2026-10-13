#if canImport(Network)
import Foundation
import Network

/// Liveness detection without raw sockets: ICMP echo (unprivileged) raced against TCP connects.
/// A refused connection (RST) proves the host is up just as well as an open port does.
public enum HostDiscovery {
    public static let probePorts: [UInt16] = [443, 80, 22, 445, 62078, 139]

    public static func isAlive(_ host: String, timeout: TimeInterval = 0.9) async -> String? {
        await withTaskGroup(of: String?.self) { group in
            #if canImport(Darwin)
            if IPv4.isIPv4(host) || !IPv4.isIP(host) {
                group.addTask { await ICMP.isAlive(host, timeout: timeout) ? "icmp-echo" : nil }
            }
            #endif
            for p in probePorts {
                group.addTask {
                    let r = await PortScanner.probeTCP(host: host, port: p, timeout: timeout, banner: false)
                    switch r.state {
                    case .open: return "tcp/\(p) open"
                    case .closed: return "tcp/\(p) reset"
                    default: return nil
                    }
                }
            }
            for await r in group {
                if let r = r { group.cancelAll(); return r }
            }
            return nil
        }
    }

    /// Returns `(host, reason)` for hosts that answered. Keeps concurrency low so we stay under the fd limit.
    public static func sweep(_ hosts: [String], concurrency: Int = 18, timeout: TimeInterval = 0.9,
                             onUp: @escaping @Sendable (String, String) -> Void = { _, _ in }) async -> [(String, String)] {
        PortScanner.raiseFileLimit()
        let found = await boundedMap(hosts, limit: concurrency) { host -> (String, String)? in
            guard let why = await isAlive(host, timeout: timeout) else { return nil }
            onUp(host, why)
            return (host, why)
        }
        return found.compactMap { $0 }.sorted {
            (IPv4.parse($0.0) ?? 0, $0.0) < (IPv4.parse($1.0) ?? 0, $1.0)
        }
    }
}
#endif
