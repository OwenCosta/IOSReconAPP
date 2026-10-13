import Foundation

public enum PortState: String, Codable, Sendable {
    case open, closed, filtered
    case openFiltered = "open|filtered"
}

public struct PortResult: Codable, Identifiable, Hashable, Sendable {
    public var host: String
    public var port: UInt16
    public var proto: String
    public var state: PortState
    public var service: String
    public var version: String?
    public var banner: String?
    public var reason: String
    public var latencyMs: Double?

    public var id: String { "\(host)|\(proto)|\(port)" }

    public init(host: String, port: UInt16, proto: String = "tcp", state: PortState,
                service: String = "", version: String? = nil, banner: String? = nil,
                reason: String = "", latencyMs: Double? = nil) {
        self.host = host
        self.port = port
        self.proto = proto
        self.state = state
        self.service = service.isEmpty ? ServiceDB.name(port: port, proto: proto) : service
        self.version = version
        self.banner = banner
        self.reason = reason
        self.latencyMs = latencyMs
    }
}

public struct HostResult: Codable, Identifiable, Hashable, Sendable {
    public var host: String
    public var alive: Bool
    public var aliveReason: String
    public var openPorts: [PortResult]
    public var closedCount: Int
    public var filteredCount: Int
    public var deviceHint: String?

    public var id: String { host }
}

// MARK: - Banner cleaning and service identification (pure; unit-tested)

public enum ServiceFingerprint {
    /// Printable, single-line, length-limited representation of raw banner bytes.
    public static func clean(_ data: Data, limit: Int = 240) -> String {
        let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) ?? ""
        var out = ""
        for u in text.unicodeScalars {
            if u == "\r" || u == "\n" || u == "\t" {
                if !out.hasSuffix(" ") { out.append(" ") }
                continue
            }
            if u.value >= 32 && u.value < 127 { out.unicodeScalars.append(u) }
            else if u.value >= 160 && u.value < 0x2FFF { out.unicodeScalars.append(u) }
            else { out.append(".") }
            if out.count >= limit { break }
        }
        return out.trimmed()
    }

    private struct Rule {
        let pattern: String
        let service: String
        let product: String?   // template using $1 (capture group)
    }

    private static let rules: [Rule] = [
        Rule(pattern: #"SSH-([0-9.]+)-OpenSSH[_-]([\w.\-]+)"#, service: "ssh", product: "OpenSSH $2 (protocol $1)"),
        Rule(pattern: #"SSH-([0-9.]+)-([\w.\-]+)"#, service: "ssh", product: "$2 (protocol $1)"),
        Rule(pattern: #"^220[ -].*\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP)[^\w]*([\d.]+)?"#,
             service: "ftp", product: "$1 $2"),
        Rule(pattern: #"^220[ -].*\bFTP\b"#, service: "ftp", product: nil),
        Rule(pattern: #"^220[ -].*\b(ESMTP|SMTP)\b.*\b(Postfix|Exim|Sendmail|Exchange|qmail)\b"#,
             service: "smtp", product: "$2"),
        Rule(pattern: #"^220[ -].*(ESMTP|SMTP)"#, service: "smtp", product: nil),
        Rule(pattern: #"^\+OK.*(Dovecot|POP3)"#, service: "pop3", product: "$1"),
        Rule(pattern: #"^\* OK.*(Dovecot|Cyrus|Courier|IMAP)"#, service: "imap", product: "$1"),
        Rule(pattern: #"^RFB ([0-9.]+)"#, service: "vnc", product: "RFB protocol $1"),
        Rule(pattern: #"(?i)Server:\s*([^\r\n]+?)(?:\s{2,}|$)"#, service: "http", product: "$1"),
        Rule(pattern: #"^HTTP/[0-9.]+ \d{3}"#, service: "http", product: nil),
        Rule(pattern: #"(?i)^-(NOAUTH|ERR|DENIED)|^\+PONG"#, service: "redis", product: nil),
        Rule(pattern: #"(?i)(\d+\.\d+\.\d+[\w\-.]*)\.{0,3}.*(mysql|mariadb)"#, service: "mysql", product: "$2 $1"),
        Rule(pattern: #"(?i)mysql_native_password|(\d+\.\d+\.\d+)-MariaDB"#, service: "mysql", product: nil),
        Rule(pattern: #"^RTSP/[0-9.]+"#, service: "rtsp", product: nil),
        Rule(pattern: #"^VERSION ([0-9.]+)"#, service: "memcached", product: "memcached $1"),
        Rule(pattern: #"(?i)^MongoDB|ismaster"#, service: "mongodb", product: nil),
        Rule(pattern: #"AMQP"#, service: "amqp", product: nil),
        Rule(pattern: #"(?i)^login:|\bwelcome to\b.*telnet|^\xFF[\xFB-\xFE]"#, service: "telnet", product: nil)
    ]

    /// Fills `service` and `version` on a result from its banner.
    public static func apply(banner: String, to result: inout PortResult) {
        result.banner = banner
        for rule in rules {
            guard let re = try? NSRegularExpression(pattern: rule.pattern, options: [.anchorsMatchLines]) else { continue }
            let ns = banner as NSString
            guard let m = re.firstMatch(in: banner, range: NSRange(location: 0, length: ns.length)) else { continue }
            result.service = rule.service
            if var tpl = rule.product {
                for i in stride(from: m.numberOfRanges - 1, through: 1, by: -1) {
                    let r = m.range(at: i)
                    let val = r.location == NSNotFound ? "" : ns.substring(with: r)
                    tpl = tpl.replacingOccurrences(of: "$\(i)", with: val)
                }
                // Drop any unreplaced placeholders
                while let r = tpl.range(of: #"\$\d"#, options: .regularExpression) { tpl.removeSubrange(r) }
                let v = tpl.trimmed()
                if !v.isEmpty { result.version = v }
            }
            return
        }
    }

    /// Payload to elicit a banner from servers that wait for the client to speak first.
    public static func probePayload(port: UInt16) -> Data? {
        if ServiceDB.httpPorts.contains(port) {
            return Data("HEAD / HTTP/1.0\r\nUser-Agent: ReconKit\r\nAccept: */*\r\n\r\n".utf8)
        }
        switch port {
        case 6379: return Data("PING\r\n".utf8)
        case 11211: return Data("version\r\n".utf8)
        case 554: return Data("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n".utf8)
        case 25, 21, 22, 110, 143, 3306: return nil          // server speaks first
        default: return Data("\r\n\r\n".utf8)
        }
    }
}
