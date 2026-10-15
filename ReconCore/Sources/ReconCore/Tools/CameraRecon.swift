import Foundation

// MARK: - IP camera reconnaissance (authorised CTF / pentest)

/// Fingerprints a host as an IP camera / NVR, then serves the brand's default
/// credentials, RTSP stream URLs and the ports worth probing. For authorised
/// engagements and CTF targets you are allowed to attack.
public enum CameraRecon {
    public struct Brand {
        public let name: String
        /// Lower-cased needles matched against Server header, WWW-Authenticate realm, HTML title/body.
        public let fingerprints: [String]
        public let creds: [(String, String)]   // user, password ("" = blank)
        public let rtsp: [String]               // path after host:port
        public let ports: [Int]
    }

    // Common camera/NVR brands with documented defaults and RTSP paths.
    public static let brands: [Brand] = [
        Brand(name: "Hikvision",
              fingerprints: ["hikvision", "app-webs", "dnvrs-webs", "dvrdvs-webs", "web service"],
              creds: [("admin", "12345"), ("admin", "Admin12345"), ("admin", "admin")],
              rtsp: ["/Streaming/Channels/101", "/Streaming/Channels/1", "/h264/ch1/main/av_stream", "/ISAPI/Streaming/channels/101"],
              ports: [80, 554, 8000, 8200]),
        Brand(name: "Dahua / Amcrest",
              fingerprints: ["dahua", "amcrest", "webs", "/rpc2", "login to"],
              creds: [("admin", "admin"), ("admin", "")],
              rtsp: ["/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1"],
              ports: [80, 554, 37777, 37778]),
        Brand(name: "Axis",
              fingerprints: ["axis", "boa/", "axis-cgi"],
              creds: [("root", "pass"), ("root", "root"), ("admin", "admin")],
              rtsp: ["/axis-media/media.amp", "/axis-media/media.amp?videocodec=h264", "/mpeg4/media.amp"],
              ports: [80, 554]),
        Brand(name: "Foscam",
              fingerprints: ["foscam", "ipcamera", "webcam"],
              creds: [("admin", ""), ("admin", "admin")],
              rtsp: ["/videoMain", "/videoSub"],
              ports: [88, 80, 554]),
        Brand(name: "Reolink",
              fingerprints: ["reolink"],
              creds: [("admin", ""), ("admin", "admin")],
              rtsp: ["/h264Preview_01_main", "/h264Preview_01_sub", "/Preview_01_main"],
              ports: [80, 554, 8000]),
        Brand(name: "Vivotek",
              fingerprints: ["vivotek", "network camera"],
              creds: [("root", ""), ("admin", "admin")],
              rtsp: ["/live.sdp", "/live2.sdp"],
              ports: [80, 554]),
        Brand(name: "Ubiquiti",
              fingerprints: ["ubiquiti", "unifi", "airvision", "ubnt"],
              creds: [("ubnt", "ubnt"), ("admin", "admin")],
              rtsp: ["/s0", "/s1"],
              ports: [80, 443, 554, 7447]),
        Brand(name: "Sony",
              fingerprints: ["sony", "no-content"],
              creds: [("admin", "admin")],
              rtsp: ["/video1", "/media/video1"],
              ports: [80, 554]),
        Brand(name: "Bosch",
              fingerprints: ["bosch", "vdg", "video streaming gateway"],
              creds: [("service", "service"), ("admin", "")],
              rtsp: ["/rtsp_tunnel", "/video"],
              ports: [80, 554]),
        Brand(name: "Panasonic",
              fingerprints: ["panasonic", "network camera"],
              creds: [("admin", "12345"), ("admin", "admin")],
              rtsp: ["/nphMpeg4/g726-640x480", "/MediaInput/h264"],
              ports: [80, 554]),
        Brand(name: "TP-Link / Tapo",
              fingerprints: ["tp-link", "tapo", "vigi"],
              creds: [("admin", "admin")],
              rtsp: ["/stream1", "/stream2", "/h264_hd.sdp"],
              ports: [80, 554, 2020]),
        Brand(name: "Wyze (RTSP firmware)",
              fingerprints: ["wyze"],
              creds: [("admin", "")],
              rtsp: ["/live"],
              ports: [554]),
    ]

    /// Generic fallbacks tried when the brand is unknown.
    public static let genericCreds: [(String, String)] = [
        ("admin", "admin"), ("admin", "12345"), ("admin", ""), ("admin", "password"),
        ("root", "root"), ("root", "pass"), ("root", "12345"), ("user", "user"), ("admin", "123456")
    ]
    public static let genericRTSP = ["/", "/live", "/live.sdp", "/stream1", "/ch0", "/0", "/video", "/media/video1"]
    public static let commonPorts = [80, 81, 88, 443, 554, 8000, 8080, 8081, 8200, 2020, 37777, 34567, 9000, 7447]

    /// Pure fingerprint: score brands against collected signals.
    public static func identify(server: String?, realm: String?, title: String?, body: String) -> [Brand] {
        let hay = [server, realm, title, String(body.prefix(4000))].compactMap { $0 }.joined(separator: " ").lowercased()
        var hits: [(Brand, Int)] = []
        for b in brands {
            let score = b.fingerprints.reduce(0) { $0 + (hay.contains($1) ? 1 : 0) }
            if score > 0 { hits.append((b, score)) }
        }
        return hits.sorted { $0.1 > $1.1 }.map(\.0)
    }

    public static func rtspURLs(host: String, brand: Brand, cred: (String, String)?) -> [String] {
        let auth = cred.map { "\($0.0):\($0.1)@" } ?? ""
        let port = brand.ports.contains(554) ? "554" : "554"
        return brand.rtsp.map { "rtsp://\(auth)\(host):\(port)\($0)" }
    }

    static func titleOf(_ html: String) -> String? {
        guard let r = html.range(of: #"(?i)<title[^>]*>(.*?)</title>"#, options: .regularExpression) else { return nil }
        return String(html[r]).replacingOccurrences(of: #"(?i)</?title[^>]*>"#, with: "", options: .regularExpression).trimmed()
    }

    public static func run(_ input: String) async -> ToolOutput {
        let host = TargetParser.stripToHost(input)
        guard !host.isEmpty else {
            return ToolOutput(sections: [ReportSection("Camera recon", items: [
                ReportItem("Usage", "enter a camera's IP or hostname (authorised targets only)", .low)])])
        }

        // Probe the common HTTP(S) camera ports and collect fingerprint signals.
        var server: String?, realm: String?, title: String?, body = ""
        var reachable: [Int] = []
        let probes: [(String, Int)] = [("http", 80), ("http", 8080), ("http", 81), ("http", 8000), ("https", 443)]
        for (scheme, port) in probes {
            guard let url = URL(string: "\(scheme)://\(host):\(port)/") else { continue }
            guard let r = try? await HTTP.request(url, timeout: 6, followRedirects: true, maxBytes: 300_000, insecureTLS: true) else { continue }
            reachable.append(port)
            if server == nil { server = r.headers["server"] }
            if realm == nil { realm = r.headers["www-authenticate"] }
            if title == nil { title = titleOf(r.text) }
            if body.isEmpty { body = r.text }
        }

        let matches = identify(server: server, realm: realm, title: title, body: body)
        var out = ToolOutput()

        var summary = ReportSection("Target \(host)", note: "Authorised testing / CTF only. Try these in a real RTSP/HTTP client.")
        summary.add("HTTP ports up", reachable.isEmpty ? "none of \(probes.map { String($0.1) }.joined(separator: ", ")) answered" : reachable.map(String.init).joined(separator: ", "),
                    reachable.isEmpty ? .info : .low)
        if let s = server { summary.add("Server", s) }
        if let r = realm { summary.add("Auth realm", r, .low) }
        if let t = title, !t.isEmpty { summary.add("Title", t) }
        summary.add("Identified", matches.isEmpty ? "unknown brand, using generic lists" : matches.map(\.name).joined(separator: ", "),
                    matches.isEmpty ? .info : .medium)
        out.sections.append(summary)

        if let brand = matches.first {
            out.findings.append(Finding(.medium, "Likely \(brand.name) camera at \(host)",
                                        "Fingerprint matched. Default credentials are a common foothold.", source: "camera"))
            var creds = ReportSection("\(brand.name) default credentials", note: "Try in the web UI or RTSP URL. Replace if the owner changed them.")
            for (u, p) in brand.creds { creds.add(u, p.isEmpty ? "(blank)" : p, .high) }
            out.sections.append(creds)

            var streams = ReportSection("RTSP stream URLs", note: "Open in VLC / ffplay. Channel/subtype may vary.")
            for (u, p) in brand.creds.prefix(1) {
                for url in rtspURLs(host: host, brand: brand, cred: (u, p)) { streams.add("", url) }
            }
            for url in rtspURLs(host: host, brand: brand, cred: nil).prefix(2) { streams.add("no-auth", url) }
            out.sections.append(streams)

            var ports = ReportSection("Ports to scan")
            ports.add(brand.name, brand.ports.map(String.init).joined(separator: ", "))
            out.sections.append(ports)
        } else {
            var creds = ReportSection("Generic camera credentials", note: "Brand unknown. Try the most common camera/NVR logins.")
            for (u, p) in genericCreds { creds.add(u, p.isEmpty ? "(blank)" : p, .medium) }
            out.sections.append(creds)
            var streams = ReportSection("Generic RTSP URLs", note: "Try these paths on port 554.")
            for path in genericRTSP { streams.add("", "rtsp://admin:admin@\(host):554\(path)") }
            out.sections.append(streams)
        }

        var tips = ReportSection("Next steps", note: nil)
        tips.add("Port scan", "Scan \(host) for \(commonPorts.map(String.init).joined(separator: ", ")) in the Scanner tab")
        tips.add("ONVIF", "Many cameras expose http://\(host)/onvif/device_service (SOAP), enumerate with an ONVIF client")
        tips.add("Snapshot", "Hikvision: /ISAPI/Streaming/channels/101/picture · Dahua: /cgi-bin/snapshot.cgi")
        tips.add("Brute", "Feed the default creds above into hydra/medusa for rtsp/http-get on a laptop if a single try fails")
        out.sections.append(tips)
        return out
    }
}

// MARK: - Wi-Fi & router recon (honest about iOS limits)

/// iOS forbids third-party Wi-Fi scanning, so this focuses on what the phone
/// *can* do: analyse the network it is on and attack the router/gateway.
public enum WiFiRecon {
    public static let routerCreds: [(String, (String, String))] = [
        ("Generic", ("admin", "admin")), ("Generic", ("admin", "password")), ("Generic", ("admin", "")),
        ("Netgear", ("admin", "password")), ("Linksys", ("admin", "admin")), ("TP-Link", ("admin", "admin")),
        ("D-Link", ("admin", "")), ("Asus", ("admin", "admin")), ("Cisco", ("cisco", "cisco")),
        ("Ubiquiti", ("ubnt", "ubnt")), ("MikroTik", ("admin", "")), ("Huawei", ("admin", "admin")),
        ("ZTE", ("admin", "admin")), ("Tenda", ("admin", "admin")), ("Xfinity", ("admin", "password"))
    ]

    public static func run(_ input: String) -> ToolOutput {
        var out = ToolOutput()
        let gw = TargetParser.stripToHost(input)

        var reality = ReportSection("Wi-Fi on iOS", note: "Honest capability list: iOS sandboxes Wi-Fi heavily.")
        reality.add("Scanning", "Third-party apps CANNOT list nearby Wi-Fi networks or read SSID/BSSID (no entitlement for sideloaded apps).", .info)
        reality.add("Monitor mode", "Not possible: no raw 802.11, no deauth, no packet capture, no evil-twin on iOS.", .info)
        reality.add("What works", "Scan the LAN you're joined to (Scan tab), discover hosts/services, and attack the router over IP.", .low)
        out.sections.append(reality)

        var attack = ReportSection(gw.isEmpty ? "Router attack checklist" : "Router attack: \(gw)",
                                   note: "Point this at your gateway (see the Home dashboard for its IP).")
        if !gw.isEmpty {
            attack.add("Admin panel", "http://\(gw)/  ·  https://\(gw)/  ·  http://\(gw):8080/")
            attack.add("Port scan", "Scan \(gw) for 22, 23, 53, 80, 443, 8080, 7547 (TR-069) in the Scanner")
            attack.add("Known paths", "/cgi-bin/, /setup.cgi, /apply.cgi, /HNAP1/ (D-Link), /tmUnblock.cgi (Linksys)")
        } else {
            attack.add("Usage", "enter your gateway IP (e.g. 192.168.1.1) for tailored URLs", .low)
        }
        out.sections.append(attack)

        var creds = ReportSection("Router default credentials")
        for (brand, c) in routerCreds { creds.add(brand, "\(c.0) / \(c.1.isEmpty ? "(blank)" : c.1)", .medium) }
        out.sections.append(creds)
        return out
    }
}
