import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

// MARK: - Digests

public enum DigestKind: String, CaseIterable, Sendable {
    case md5 = "MD5", sha1 = "SHA-1", sha256 = "SHA-256", sha384 = "SHA-384", sha512 = "SHA-512"
}

public enum Digests {
    /// Hex digest. Uses CryptoKit on Apple platforms and a portable implementation elsewhere.
    public static func hex(_ kind: DigestKind, _ data: Data) -> String? {
        #if canImport(CryptoKit)
        func h<D: Digest>(_ d: D) -> String { d.map { String(format: "%02x", $0) }.joined() }
        switch kind {
        case .md5: return h(Insecure.MD5.hash(data: data))
        case .sha1: return h(Insecure.SHA1.hash(data: data))
        case .sha256: return h(SHA256.hash(data: data))
        case .sha384: return h(SHA384.hash(data: data))
        case .sha512: return h(SHA512.hash(data: data))
        }
        #else
        let bytes = [UInt8](data)
        switch kind {
        case .md5: return PureHash.hex(PureHash.md5(bytes))
        case .sha1: return PureHash.hex(PureHash.sha1(bytes))
        case .sha256: return PureHash.hex(PureHash.sha256(bytes))
        case .sha384, .sha512: return nil   // 64-bit SHA-2 not implemented in the portable fallback
        }
        #endif
    }

    public static func hex(_ kind: DigestKind, _ s: String) -> String? { hex(kind, Data(s.utf8)) }
}

// MARK: - Encoders / decoders

public enum Encoders {
    public static func base64Decode(_ s: String) -> Data? {
        var t = s.trimmed().replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        t = t.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: " ", with: "")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    public static func hexDecode(_ s: String) -> Data? {
        let t = s.trimmed().replacingOccurrences(of: "0x", with: "").replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: ":", with: "")
        guard !t.isEmpty, t.count % 2 == 0, t.allSatisfy({ $0.isHexDigit }) else { return nil }
        var data = Data(capacity: t.count / 2)
        var i = t.startIndex
        while i < t.endIndex {
            let j = t.index(i, offsetBy: 2)
            data.append(UInt8(t[i..<j], radix: 16)!)
            i = j
        }
        return data
    }

    public static func rot13(_ s: String) -> String {
        String(s.unicodeScalars.map { u -> Character in
            switch u.value {
            case 65...90: return Character(UnicodeScalar((u.value - 65 + 13) % 26 + 65)!)
            case 97...122: return Character(UnicodeScalar((u.value - 97 + 13) % 26 + 97)!)
            default: return Character(u)
            }
        })
    }

    static func printable(_ d: Data) -> String? {
        guard let s = String(data: d, encoding: .utf8), !s.isEmpty else { return nil }
        let bad = s.unicodeScalars.filter { $0.value < 9 || ($0.value > 13 && $0.value < 32) }.count
        return bad == 0 ? s : nil
    }

    /// Try every common decoding and show what sticks.
    public static func decodeAll(_ input: String) -> ReportSection {
        var s = ReportSection("Decodings")
        if let d = base64Decode(input), let t = printable(d) { s.add("Base64 / Base64URL", t) }
        if let d = hexDecode(input), let t = printable(d) { s.add("Hex", t) }
        if let t = input.removingPercentEncoding, t != input { s.add("URL-decoded", t) }
        let r = rot13(input)
        if r != input { s.add("ROT13", r) }
        s.add("Base64 encode", Data(input.utf8).base64EncodedString())
        s.add("Hex encode", Data(input.utf8).map { String(format: "%02x", $0) }.joined())
        s.add("URL encode", input.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? input)
        return s
    }
}

// MARK: - JWT

public enum JWT {
    public static func analyze(_ token: String) -> ToolOutput {
        var out = ToolOutput()
        let parts = token.trimmed().split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 || parts.count == 2 else {
            out.sections = [ReportSection("JWT", items: [ReportItem("Error", "Not a JWT (expected header.payload.signature)", .high)])]
            return out
        }
        func decode(_ p: String) -> [String: Any]? {
            guard let d = Encoders.base64Decode(p),
                  let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return nil }
            return o
        }
        func pretty(_ o: [String: Any]) -> String {
            guard let d = try? JSONSerialization.data(withJSONObject: o, options: [.prettyPrinted, .sortedKeys]) else { return "" }
            return String(data: d, encoding: .utf8) ?? ""
        }

        guard let header = decode(parts[0]), let payload = decode(parts[1]) else {
            out.sections = [ReportSection("JWT", items: [ReportItem("Error", "Header or payload is not valid base64url JSON", .high)])]
            return out
        }
        var hs = ReportSection("Header")
        hs.add("JSON", pretty(header))
        let alg = (header["alg"] as? String) ?? "?"
        hs.add("Algorithm", alg)
        if alg.lowercased() == "none" {
            hs.add("Risk", "alg=none: signature not verified – accept only if server rejects unsigned tokens", .critical)
            out.findings.append(Finding(.critical, "JWT uses alg=none", "Unsigned tokens may be accepted by misconfigured servers.", source: "jwt"))
        } else if alg.hasPrefix("HS") {
            hs.add("Note", "Symmetric HMAC – test for weak/guessable signing secrets and RS→HS confusion", .low)
        }
        if header["jku"] != nil || header["x5u"] != nil || header["jwk"] != nil {
            hs.add("Risk", "Token carries key-source headers (jku/x5u/jwk) – test for key injection", .medium)
        }
        if header["kid"] != nil { hs.add("kid", "\(header["kid"]!) – test kid for path traversal / SQLi", .low) }

        var ps = ReportSection("Payload")
        ps.add("JSON", pretty(payload))
        let fmt = ISO8601DateFormatter()
        let now = Date().timeIntervalSince1970
        for key in ["iat", "nbf", "exp"] {
            if let n = payload[key] as? NSNumber {
                let t = n.doubleValue
                var sev: Severity = .info
                var note = fmt.string(from: Date(timeIntervalSince1970: t))
                if key == "exp" { if t < now { note += "  (EXPIRED)"; sev = .low } else { note += "  (valid)" } }
                ps.add(key, note, sev)
            }
        }
        if payload["exp"] == nil { ps.add("exp", "no expiry – token never expires", .medium) }
        if parts.count == 3 && parts[2].isEmpty && alg.lowercased() != "none" {
            ps.add("Signature", "empty signature segment", .high)
        }
        out.sections = [hs, ps]
        return out
    }
}

// MARK: - Hash identification

public enum HashIdentifier {
    struct Rule { let name: String; let pattern: String; let hashcat: String }
    static let rules: [Rule] = [
        .init(name: "bcrypt", pattern: #"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$"#, hashcat: "3200"),
        .init(name: "Argon2", pattern: #"^\$argon2(id|i|d)\$.+"#, hashcat: "n/a (argon2)"),
        .init(name: "SHA-512 crypt ($6$)", pattern: #"^\$6\$.+\$[./A-Za-z0-9]{86}$"#, hashcat: "1800"),
        .init(name: "SHA-256 crypt ($5$)", pattern: #"^\$5\$.+\$[./A-Za-z0-9]{43}$"#, hashcat: "7400"),
        .init(name: "MD5 crypt ($1$)", pattern: #"^\$1\$.{1,8}\$[./A-Za-z0-9]{22}$"#, hashcat: "500"),
        .init(name: "phpass / WordPress ($P$ $H$)", pattern: #"^\$[PH]\$[./A-Za-z0-9]{31}$"#, hashcat: "400"),
        .init(name: "Django PBKDF2-SHA256", pattern: #"^pbkdf2_sha256\$\d+\$.+\$.+$"#, hashcat: "10000"),
        .init(name: "MySQL 4.1+ (SHA1(SHA1))", pattern: #"^\*[A-F0-9]{40}$"#, hashcat: "300"),
        .init(name: "SHA-512", pattern: #"^[a-fA-F0-9]{128}$"#, hashcat: "1700"),
        .init(name: "SHA-384", pattern: #"^[a-fA-F0-9]{96}$"#, hashcat: "10800"),
        .init(name: "SHA-256", pattern: #"^[a-fA-F0-9]{64}$"#, hashcat: "1400"),
        .init(name: "SHA-1 (or MySQL < 4.1 / RIPEMD-160 variants)", pattern: #"^[a-fA-F0-9]{40}$"#, hashcat: "100"),
        .init(name: "NTLM / MD5 / MD4 / LM (32 hex)", pattern: #"^[a-fA-F0-9]{32}$"#, hashcat: "1000 (NTLM) / 0 (MD5)"),
        .init(name: "CRC-32 / Adler-32 (8 hex)", pattern: #"^[a-fA-F0-9]{8}$"#, hashcat: "11500"),
        .init(name: "NetNTLMv2", pattern: #"^[^:]+::[^:]*:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$"#, hashcat: "5600"),
        .init(name: "JWT", pattern: #"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$"#, hashcat: "16500 (HS*)")
    ]

    public static func identify(_ input: String) -> ReportSection {
        let h = input.trimmed()
        var s = ReportSection("Hash identification")
        s.add("Input length", "\(h.count) characters")
        var matched = false
        for r in rules where h.range(of: r.pattern, options: .regularExpression) != nil {
            s.add("Candidate", "\(r.name)   [hashcat -m \(r.hashcat)]")
            matched = true
        }
        if !matched { s.add("Result", "No known hash format matched", .low) }
        return s
    }

    public static func generate(_ input: String) -> ReportSection {
        var s = ReportSection("Digests of input")
        for k in DigestKind.allCases { s.add(k.rawValue, Digests.hex(k, input) ?? "unavailable on this platform") }
        return s
    }
}

// MARK: - Password strength (offline)

public enum PasswordStrength {
    public static func entropyBits(_ pw: String) -> Double {
        guard !pw.isEmpty else { return 0 }
        var pool = 0
        if pw.contains(where: { $0.isLowercase }) { pool += 26 }
        if pw.contains(where: { $0.isUppercase }) { pool += 26 }
        if pw.contains(where: { $0.isNumber }) { pool += 10 }
        if pw.contains(where: { !$0.isLetter && !$0.isNumber }) { pool += 33 }
        return Double(pw.count) * log2(Double(max(pool, 1)))
    }
}
