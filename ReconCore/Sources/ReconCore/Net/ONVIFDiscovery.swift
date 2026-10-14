import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// A device found via WS-Discovery — almost always an ONVIF camera/NVR, but also
/// printers and other WS-Discovery-compatible gear.
public struct ONVIFDevice: Identifiable, Sendable, Equatable {
    public var xaddrs: [String]      // device service URLs, e.g. http://192.168.1.64/onvif/device_service
    public var types: [String]
    public var scopes: [String]
    public var name: String?
    public var hardware: String?
    public var location: String?
    public var id: String { xaddrs.first ?? scopes.joined() }

    /// The camera's LAN host/IP, parsed from its first XAddr.
    public var host: String? {
        guard let first = xaddrs.first, let url = URL(string: first) else { return nil }
        return url.host
    }
    public var isLikelyCamera: Bool {
        types.contains { $0.lowercased().contains("networkvideotransmitter") || $0.lowercased().contains("nvt") }
    }
}

/// WS-Discovery (the protocol ONVIF cameras use to announce themselves) over UDP
/// multicast, so cameras already on your joined Wi-Fi are found automatically —
/// no address guessing or port scanning needed. Uses the same unprivileged raw
/// Darwin sockets technique as ICMP.swift.
public enum ONVIFDiscovery {
    static let multicastAddress = "239.255.255.250"
    static let multicastPort: UInt16 = 3702

    /// Build one WS-Discovery Probe SOAP request. `types` nil = a generic probe
    /// that most WS-Discovery devices answer; "dn:NetworkVideoTransmitter" targets
    /// ONVIF cameras specifically.
    static func probeMessage(types: String?, messageID: String = UUID().uuidString) -> String {
        let typesElement = types.map { "<d:Types>\($0)</d:Types>" } ?? ""
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
        <e:Header>
        <w:MessageID>uuid:\(messageID)</w:MessageID>
        <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
        <w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
        </e:Header>
        <e:Body>
        <d:Probe>\(typesElement)</d:Probe>
        </e:Body>
        </e:Envelope>
        """
    }

    /// Parse one WS-Discovery ProbeMatch SOAP response. Pure, testable without a network.
    public static func parseProbeMatch(_ xml: String) -> ONVIFDevice? {
        guard xml.contains("ProbeMatch") else { return nil }
        guard let xaddrsRaw = firstMatch(#"(?s)<[^:>]*:?XAddrs>(.*?)</[^:>]*:?XAddrs>"#, in: xml), !xaddrsRaw.trimmed().isEmpty else { return nil }
        let scopesRaw = firstMatch(#"(?s)<[^:>]*:?Scopes[^>]*>(.*?)</[^:>]*:?Scopes>"#, in: xml) ?? ""
        let typesRaw = firstMatch(#"(?s)<[^:>]*:?Types>(.*?)</[^:>]*:?Types>"#, in: xml) ?? ""

        let xaddrs = xaddrsRaw.split(whereSeparator: \.isWhitespace).map(String.init)
        let scopes = scopesRaw.split(whereSeparator: \.isWhitespace).map(String.init)
        let types = typesRaw.split(whereSeparator: \.isWhitespace).map(String.init)
        guard !xaddrs.isEmpty else { return nil }

        let info = friendlyInfo(from: scopes)
        return ONVIFDevice(xaddrs: xaddrs, types: types, scopes: scopes, name: info.name, hardware: info.hardware, location: info.location)
    }

    /// Extract name/hardware/location from ONVIF scope URIs, e.g.
    /// `onvif://www.onvif.org/name/My%20Camera` → name "My Camera".
    public static func friendlyInfo(from scopes: [String]) -> (name: String?, hardware: String?, location: String?) {
        var name: String?, hardware: String?, location: String?
        for s in scopes {
            guard let url = URL(string: s), url.scheme?.lowercased() == "onvif" else { continue }
            let comps = url.path.split(separator: "/").map(String.init)
            guard let key = comps.first else { continue }
            let value = comps.dropFirst().joined(separator: "/").removingPercentEncoding ?? comps.dropFirst().joined(separator: "/")
            guard !value.isEmpty else { continue }
            switch key.lowercased() {
            case "name": name = value
            case "hardware": hardware = value
            case "location": location = value
            default: break
            }
        }
        return (name, hardware, location)
    }

    static func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        let ns = text as NSString
        guard let m = re.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)), m.numberOfRanges > 1 else { return nil }
        return ns.substring(with: m.range(at: 1))
    }

    #if canImport(Darwin)
    /// Probe the LAN for ONVIF/WS-Discovery devices and collect their replies for `timeout` seconds.
    public static func discover(timeout: TimeInterval = 4) async -> [ONVIFDevice] {
        await background { runBlocking(timeout: timeout) }
    }

    static func background<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async { cont.resume(returning: work()) }
        }
    }

    static func runBlocking(timeout: TimeInterval) -> [ONVIFDevice] {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return [] }
        defer { close(fd) }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var ttl: Int32 = 4
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, socklen_t(MemoryLayout<Int32>.size))

        var local = sockaddr_in()
        local.sin_family = sa_family_t(AF_INET)
        local.sin_port = 0
        local.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &local) { p -> Int32 in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { return [] }

        var dest = sockaddr_in()
        dest.sin_family = sa_family_t(AF_INET)
        dest.sin_port = multicastPort.bigEndian
        inet_pton(AF_INET, multicastAddress, &dest.sin_addr)

        // A targeted probe for ONVIF cameras, plus a generic probe that catches
        // other WS-Discovery gear (some NVRs only answer the untyped probe).
        for msg in [probeMessage(types: "dn:NetworkVideoTransmitter"), probeMessage(types: nil)] {
            let bytes = Array(msg.utf8)
            _ = bytes.withUnsafeBytes { buf in
                withUnsafePointer(to: &dest) { dp in
                    dp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        sendto(fd, buf.baseAddress, buf.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
        }

        var found: [String: ONVIFDevice] = [:]
        let deadline = Date().addingTimeInterval(timeout)
        var buf = [UInt8](repeating: 0, count: 16384)
        while Date() < deadline {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { break }
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
                if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
                break
            }
            guard n > 0, let xml = String(data: Data(buf[0..<n]), encoding: .utf8),
                  let device = parseProbeMatch(xml) else { continue }
            found[device.id] = device
        }
        return Array(found.values)
    }
    #endif
}
