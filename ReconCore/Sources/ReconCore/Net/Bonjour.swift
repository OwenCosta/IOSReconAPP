#if canImport(Network)
import Foundation
import Network

public struct BonjourService: Codable, Identifiable, Hashable, Sendable {
    public var name: String
    public var type: String
    public var domain: String
    public var addresses: [String]
    public var port: Int?
    public var txt: [String: String]
    public var id: String { "\(name)|\(type)|\(domain)" }

    public var friendlyType: String {
        Bonjour.labels[type] ?? type
    }
}

/// mDNS / Bonjour service discovery. Requires NSLocalNetworkUsageDescription and the service types
/// listed under NSBonjourServices in Info.plist (this project's project.yml already does that).
public enum Bonjour {
    public static let labels: [String: String] = [
        "_http._tcp": "Web server", "_https._tcp": "Secure web server", "_ssh._tcp": "SSH", "_sftp-ssh._tcp": "SFTP",
        "_smb._tcp": "SMB file sharing", "_afpovertcp._tcp": "AFP file sharing", "_airplay._tcp": "AirPlay",
        "_raop._tcp": "AirPlay audio", "_ipp._tcp": "Printer (IPP)", "_printer._tcp": "Printer (LPD)",
        "_hap._tcp": "HomeKit accessory", "_googlecast._tcp": "Chromecast", "_spotify-connect._tcp": "Spotify Connect",
        "_companion-link._tcp": "Apple device", "_device-info._tcp": "Device info", "_workstation._tcp": "Workstation",
        "_rfb._tcp": "VNC / Screen Sharing", "_daap._tcp": "iTunes library", "_mediaremotetv._tcp": "Apple TV",
        "_homekit._tcp": "HomeKit", "_ftp._tcp": "FTP", "_telnet._tcp": "Telnet", "_nfs._tcp": "NFS",
        "_adisk._tcp": "Time Machine disk", "_sleep-proxy._udp": "Sleep proxy"
    ]

    public static var serviceTypes: [String] { Array(labels.keys).sorted() }

    private final class Collector: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [String: (name: String, type: String, domain: String, endpoint: NWEndpoint, txt: [String: String])] = [:]
        func add(_ r: NWBrowser.Result, type: String) {
            guard case let .service(name, t, domain, _) = r.endpoint else { return }
            var txt: [String: String] = [:]
            if case let .bonjour(record) = r.metadata { txt = record.dictionary }
            lock.lock(); items["\(name)|\(t)|\(domain)"] = (name, type, domain, r.endpoint, txt); lock.unlock()
        }
        var all: [(name: String, type: String, domain: String, endpoint: NWEndpoint, txt: [String: String])] {
            lock.lock(); defer { lock.unlock() }; return Array(items.values)
        }
    }

    public static func browse(types: [String] = serviceTypes, duration: TimeInterval = 6) async -> [BonjourService] {
        let collector = Collector()
        let queue = DispatchQueue(label: "recon.bonjour")
        var browsers: [NWBrowser] = []
        for t in types {
            let b = NWBrowser(for: .bonjourWithTXTRecord(type: t, domain: "local."), using: .init())
            b.browseResultsChangedHandler = { results, _ in for r in results { collector.add(r, type: t) } }
            b.start(queue: queue)
            browsers.append(b)
        }
        try? await Task.sleep(nanoseconds: UInt64(duration * 1_000_000_000))
        browsers.forEach { $0.cancel() }

        // Resolve each service to an address by briefly connecting to its endpoint.
        let found = collector.all
        let resolved = await boundedMap(Array(found.prefix(60)), limit: 12) { item -> BonjourService in
            let (addr, port) = await resolve(item.endpoint)
            return BonjourService(name: item.name, type: item.type, domain: item.domain,
                                  addresses: addr, port: port, txt: item.txt)
        }
        return resolved.sorted { ($0.type, $0.name) < ($1.type, $1.name) }
    }

    private static func resolve(_ endpoint: NWEndpoint) async -> ([String], Int?) {
        await withCheckedContinuation { (cont: CheckedContinuation<([String], Int?), Never>) in
            let conn = NWConnection(to: endpoint, using: .tcp)
            let gate = Gate()
            let q = DispatchQueue(label: "recon.bonjour.resolve")
            func finish() {
                guard gate.claim() else { return }
                var addrs: [String] = []
                var port: Int?
                if let remote = conn.currentPath?.remoteEndpoint, case let .hostPort(host, p) = remote {
                    var s = "\(host)"
                    if let pct = s.firstIndex(of: "%") { s = String(s[..<pct]) }
                    addrs = [s]
                    port = Int(p.rawValue)
                }
                conn.stateUpdateHandler = nil
                conn.cancel()
                cont.resume(returning: (addrs, port))
            }
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready, .failed, .waiting: finish()
                default: break
                }
            }
            conn.start(queue: q)
            q.asyncAfter(deadline: .now() + 2.5) { finish() }
        }
    }
}
#endif
