import Foundation
#if canImport(Network)
import Network
import Security
#endif

public struct TLSSnapshot: Sendable {
    public var host: String
    public var port: UInt16
    public var negotiatedVersion: String?
    public var cipher: String?
    public var alpn: String?
    public var chain: [X509Info]
    public var trusted: Bool
    public var trustError: String?
    /// Protocol → accepted by server (only versions we managed to test)
    public var protocolSupport: [(name: String, supported: Bool)]
}

public enum TLSAnalysis {
    public static func output(_ s: TLSSnapshot) -> ToolOutput {
        var out = ToolOutput()
        var conn = ReportSection("TLS connection  \(s.host):\(s.port)")
        conn.add("Negotiated", s.negotiatedVersion ?? "unknown")
        conn.add("Cipher suite", s.cipher ?? "unknown")
        if let a = s.alpn { conn.add("ALPN", a) }
        conn.add("Chain trusted by iOS", s.trusted ? "yes" : "NO: \(s.trustError ?? "validation failed")", s.trusted ? .info : .high)
        if !s.trusted {
            out.findings.append(Finding(.high, "Untrusted certificate on \(s.host):\(s.port)", s.trustError ?? "", source: "tls"))
        }
        if let v = s.negotiatedVersion, v.contains("1.0") || v.contains("1.1") {
            out.findings.append(Finding(.medium, "Legacy TLS negotiated on \(s.host):\(s.port)", v, source: "tls"))
        }
        out.sections.append(conn)

        if !s.protocolSupport.isEmpty {
            var p = ReportSection("Protocol support",
                                  note: "Tested by forcing each version. iOS disables TLS 1.0/1.1 system-wide, so a “rejected” there reflects this device, not proof the server disabled it.")
            for (name, ok) in s.protocolSupport {
                let legacy = name.contains("1.0") || name.contains("1.1")
                p.add(name, ok ? "accepted" : "rejected", ok && legacy ? .medium : .info)
                if ok && legacy {
                    out.findings.append(Finding(.medium, "\(name) enabled on \(s.host):\(s.port)",
                                                "Deprecated protocol (RFC 8996); disable it.", source: "tls"))
                }
            }
            out.sections.append(p)
        }

        for (i, c) in s.chain.enumerated() {
            let role = i == 0 ? "Leaf certificate" : (c.selfSigned ? "Root certificate" : "Intermediate #\(i)")
            var sec = ReportSection(role)
            sec.add("Subject", c.subject)
            sec.add("Issuer", c.issuer)
            sec.add("Valid from", fmt(c.notBefore))
            var expSev: Severity = .info
            var expNote = fmt(c.notAfter) + "  (\(c.daysRemaining) days left)"
            if c.isExpired { expSev = .critical; expNote = fmt(c.notAfter) + "  EXPIRED" }
            else if c.daysRemaining < 14 { expSev = .high }
            else if c.daysRemaining < 30 { expSev = .medium }
            sec.add("Valid until", expNote, expSev)
            sec.add("Lifetime", "\(c.validityDays) days")
            sec.add("Key", "\(c.keyAlgorithm)" + (c.keyBits.map { " \($0)-bit" } ?? ""),
                    (c.keyAlgorithm == "RSA" && (c.keyBits ?? 4096) < 2048) ? .high : .info)
            let weakSig = c.signatureAlgorithm.lowercased().contains("md5") || c.signatureAlgorithm.lowercased().contains("sha1")
            sec.add("Signature", c.signatureAlgorithm, weakSig ? .high : .info)
            sec.add("Serial", c.serialHex)
            sec.add("SHA-256", c.sha256)
            sec.add("SHA-1", c.sha1)
            if i == 0 {
                sec.add("Subject Alt Names", c.subjectAltNames.isEmpty ? "none" : c.subjectAltNames.joined(separator: "\n"))
                let match = X509.hostMatches(s.host, names: c.subjectAltNames.isEmpty ? [c.subjectCN] : c.subjectAltNames)
                if !IPv4.isIP(s.host) {
                    sec.add("Hostname match", match ? "yes" : "NO: certificate not valid for \(s.host)", match ? .info : .high)
                    if !match { out.findings.append(Finding(.high, "Certificate name mismatch for \(s.host)", "SANs: \(c.subjectAltNames.joined(separator: ", "))", source: "tls")) }
                }
                if c.selfSigned { sec.add("Self-signed", "yes", .high); out.findings.append(Finding(.high, "Self-signed certificate on \(s.host):\(s.port)", "", source: "tls")) }
                if c.validityDays > 398 { sec.add("Lifetime policy", "exceeds 398-day browser limit", .low) }
            }
            if c.isExpired { out.findings.append(Finding(.critical, "Expired certificate: \(c.subjectCN)", "Expired \(fmt(c.notAfter))", source: "tls")) }
            else if c.daysRemaining < 30 && i == 0 {
                out.findings.append(Finding(c.daysRemaining < 14 ? .high : .medium, "Certificate for \(s.host) expires in \(c.daysRemaining) days", "", source: "tls"))
            }
            if weakSig { out.findings.append(Finding(.high, "Weak signature algorithm (\(c.signatureAlgorithm)) on \(c.subjectCN)", "", source: "tls")) }
            if c.keyAlgorithm == "RSA", (c.keyBits ?? 4096) < 2048 {
                out.findings.append(Finding(.high, "RSA key under 2048 bits on \(c.subjectCN)", "\(c.keyBits ?? 0)-bit", source: "tls"))
            }
            out.sections.append(sec)
        }
        return out
    }

    static func fmt(_ d: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm 'UTC'"
        f.timeZone = TimeZone(identifier: "UTC")
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: d)
    }
}

#if canImport(Network)
public enum TLSInspector {
    private final class Capture: @unchecked Sendable {
        private let lock = NSLock()
        private var _trust: SecTrust?
        var trust: SecTrust? { lock.lock(); defer { lock.unlock() }; return _trust }
        func set(_ t: SecTrust) { lock.lock(); _trust = t; lock.unlock() }
    }

    static func versionName(_ raw: UInt16) -> String {
        switch raw {
        case 0x0301: return "TLS 1.0"
        case 0x0302: return "TLS 1.1"
        case 0x0303: return "TLS 1.2"
        case 0x0304: return "TLS 1.3"
        default: return String(format: "0x%04X", raw)
        }
    }

    static let ciphers: [UInt16: String] = [
        0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
        0xC02B: "ECDHE_ECDSA_AES_128_GCM_SHA256", 0xC02C: "ECDHE_ECDSA_AES_256_GCM_SHA384",
        0xC02F: "ECDHE_RSA_AES_128_GCM_SHA256", 0xC030: "ECDHE_RSA_AES_256_GCM_SHA384",
        0xCCA8: "ECDHE_RSA_CHACHA20_POLY1305", 0xCCA9: "ECDHE_ECDSA_CHACHA20_POLY1305",
        0xC013: "ECDHE_RSA_AES_128_CBC_SHA", 0xC014: "ECDHE_RSA_AES_256_CBC_SHA",
        0xC009: "ECDHE_ECDSA_AES_128_CBC_SHA", 0xC00A: "ECDHE_ECDSA_AES_256_CBC_SHA",
        0x009C: "RSA_AES_128_GCM_SHA256", 0x009D: "RSA_AES_256_GCM_SHA384",
        0x002F: "RSA_AES_128_CBC_SHA", 0x0035: "RSA_AES_256_CBC_SHA"
    ]

    private struct Handshake {
        var version: String?
        var cipher: String?
        var alpn: String?
        var trust: SecTrust?
    }

    /// One TLS handshake. Certificate validation is intentionally bypassed inside the handshake so
    /// expired / self-signed / mismatched certificates can still be inspected; trust is evaluated afterwards.
    private static func handshake(host: String, port: UInt16, timeout: TimeInterval,
                                  minVersion: tls_protocol_version_t? = nil,
                                  maxVersion: tls_protocol_version_t? = nil) async -> Handshake? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let capture = Capture()
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        if !IPv4.isIP(host) { sec_protocol_options_set_tls_server_name(sec, host) }
        sec_protocol_options_add_tls_application_protocol(sec, "h2")
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        if let v = minVersion { sec_protocol_options_set_min_tls_protocol_version(sec, v) }
        if let v = maxVersion { sec_protocol_options_set_max_tls_protocol_version(sec, v) }
        sec_protocol_options_set_verify_block(sec, { _, trust, complete in
            capture.set(sec_trust_copy_ref(trust).takeRetainedValue())
            complete(true)
        }, DispatchQueue(label: "recon.tls.verify"))

        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort,
                                using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()))
        let gate = Gate()
        let q = DispatchQueue(label: "recon.tls.\(host)")

        return await withCheckedContinuation { (cont: CheckedContinuation<Handshake?, Never>) in
            func finish(_ ok: Bool) {
                guard gate.claim() else { return }
                var hs = Handshake(trust: capture.trust)
                if ok, let meta = conn.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata {
                    let sm = meta.securityProtocolMetadata
                    hs.version = versionName(sec_protocol_metadata_get_negotiated_tls_protocol_version(sm).rawValue)
                    let cs = sec_protocol_metadata_get_negotiated_tls_ciphersuite(sm).rawValue
                    hs.cipher = ciphers[cs] ?? String(format: "0x%04X", cs)
                    if let p = sec_protocol_metadata_get_negotiated_protocol(sm) { hs.alpn = String(cString: p) }
                }
                conn.stateUpdateHandler = nil
                conn.cancel()
                cont.resume(returning: ok ? hs : nil)
            }
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready: finish(true)
                case .failed, .cancelled: finish(false)
                case .waiting: finish(false)
                default: break
                }
            }
            conn.start(queue: q)
            q.asyncAfter(deadline: .now() + timeout) { finish(false) }
        }
    }

    public static func inspect(host: String, port: UInt16 = 443, timeout: TimeInterval = 8,
                               probeProtocols: Bool = true) async throws -> TLSSnapshot {
        guard let hs = await handshake(host: host, port: port, timeout: timeout) else {
            throw ReconError.network("TLS handshake with \(host):\(port) failed (no TLS service, filtered, or protocol error)")
        }
        var chain: [X509Info] = []
        var trusted = false
        var trustErr: String?
        if let trust = hs.trust {
            let policy = SecPolicyCreateSSL(true, IPv4.isIP(host) ? nil : host as CFString)
            SecTrustSetPolicies(trust, policy)
            var err: CFError?
            trusted = SecTrustEvaluateWithError(trust, &err)
            if !trusted { trustErr = err.map { CFErrorCopyDescription($0) as String } }
            if let certs = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
                chain = certs.compactMap { X509.parse(der: SecCertificateCopyData($0) as Data) }
            }
        }

        var support: [(String, Bool)] = []
        if probeProtocols {
            let versions: [(String, tls_protocol_version_t)] = [("TLS 1.0", .TLSv10), ("TLS 1.1", .TLSv11),
                                                                ("TLS 1.2", .TLSv12), ("TLS 1.3", .TLSv13)]
            let results = await withTaskGroup(of: (Int, Bool).self) { group -> [(Int, Bool)] in
                for (i, v) in versions.enumerated() {
                    group.addTask {
                        let ok = await handshake(host: host, port: port, timeout: 5, minVersion: v.1, maxVersion: v.1) != nil
                        return (i, ok)
                    }
                }
                var r: [(Int, Bool)] = []
                for await x in group { r.append(x) }
                return r.sorted { $0.0 < $1.0 }
            }
            support = results.map { (versions[$0.0].0, $0.1) }
        }
        return TLSSnapshot(host: host, port: port, negotiatedVersion: hs.version, cipher: hs.cipher, alpn: hs.alpn,
                           chain: chain, trusted: trusted, trustError: trustErr, protocolSupport: support)
    }
}
#endif
