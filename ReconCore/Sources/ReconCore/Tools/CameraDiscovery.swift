import Foundation

/// Finds cameras already on the Wi-Fi you're joined to — automatically, with no
/// address guessing or port scanning of the whole subnet. Combines WS-Discovery
/// (the multicast protocol ONVIF cameras use to announce themselves) with
/// mDNS/Bonjour, then runs full camera recon (brand fingerprint, default
/// credentials, RTSP URLs) against every host found.
public enum CameraDiscovery {
    struct Hit: Sendable { let host: String; let method: String; let label: String }

    public static func run(_ input: String) async -> ToolOutput {
        let seconds = Double(input.trimmed()) ?? 5
        let duration = max(3.0, min(seconds, 15.0))

        let onvifHits = await discoverONVIF(timeout: duration)
        let mdnsHits = await discoverMDNSCameras(timeout: duration)

        var out = ToolOutput()
        var hosts: [String: Hit] = [:]

        var onvifSection = ReportSection("WS-Discovery / ONVIF (\(onvifHits.count) found)",
                                         note: "Cameras announce themselves over multicast — no scanning or address guessing needed. Only reaches this subnet.")
        if onvifHits.isEmpty { onvifSection.add("Result", "no ONVIF/WS-Discovery devices responded in \(Int(duration))s", .info) }
        for d in onvifHits {
            guard let host = d.host else { continue }
            let label = d.name ?? d.hardware ?? "ONVIF device"
            let detail = [d.hardware, d.location].compactMap { $0 }.joined(separator: " · ")
            onvifSection.add(host, detail.isEmpty ? label : "\(label) (\(detail))", d.isLikelyCamera ? .high : .medium)
            hosts[host] = Hit(host: host, method: "ONVIF", label: label)
        }
        out.sections.append(onvifSection)

        var mdnsSection = ReportSection("mDNS / Bonjour — camera-sounding services (\(mdnsHits.count))")
        if mdnsHits.isEmpty { mdnsSection.add("Result", "no camera-like mDNS services found", .info) }
        for hit in mdnsHits {
            mdnsSection.add(hit.host, "\(hit.label) — \(hit.type)")
            hosts[hit.host] = Hit(host: hit.host, method: "mDNS", label: hit.label)
        }
        out.sections.append(mdnsSection)

        guard !hosts.isEmpty else {
            out.sections.append(ReportSection("Next steps", items: [
                ReportItem("No cameras auto-discovered", "Try IP Camera Recon with a specific IP, or re-run while on the camera's own Wi-Fi/VLAN — WS-Discovery and mDNS only reach the local subnet.", .low)
            ]))
            return out
        }

        // Full recon (fingerprint, default creds, RTSP URLs) against every host found.
        let recon = await boundedMap(Array(hosts.values.prefix(8)), limit: 4) { hit in (hit, await CameraRecon.run(hit.host)) }
        for (hit, result) in recon {
            var merged = result
            if !merged.sections.isEmpty { merged.sections[0].title = "\(hit.host) — found via \(hit.method)" }
            out.sections.append(contentsOf: merged.sections)
            out.findings.append(contentsOf: merged.findings)
        }
        return out
    }

    #if canImport(Darwin)
    private static func discoverONVIF(timeout: Double) async -> [ONVIFDevice] {
        await ONVIFDiscovery.discover(timeout: timeout)
    }
    #else
    private static func discoverONVIF(timeout: Double) async -> [ONVIFDevice] { [] }
    #endif

    #if canImport(Network)
    private static func discoverMDNSCameras(timeout: Double) async -> [(host: String, label: String, type: String)] {
        let types = Array(Set(Bonjour.serviceTypes + ["_rtsp._tcp", "_axis-video._tcp"]))
        let services = await Bonjour.browse(types: types, duration: timeout)
        return services.compactMap { svc in
            guard let host = svc.addresses.first else { return nil }
            let hay = (svc.name + " " + svc.type).lowercased()
            let looksLikeCamera = BLEClassifier.cameraNames.contains { hay.contains($0) } || svc.type.contains("rtsp") || svc.type.contains("axis")
            guard looksLikeCamera else { return nil }
            return (host, svc.name, svc.friendlyType)
        }
    }
    #else
    private static func discoverMDNSCameras(timeout: Double) async -> [(host: String, label: String, type: String)] { [] }
    #endif
}
