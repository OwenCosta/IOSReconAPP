import Foundation

// MARK: - Minimal DER reader

struct ASN1Node {
    let tag: UInt8
    let value: [UInt8]
    let raw: [UInt8]

    var children: [ASN1Node] { ASN1.parse(value) }
}

enum ASN1 {
    static func parse(_ bytes: [UInt8]) -> [ASN1Node] {
        var out: [ASN1Node] = []
        var i = 0
        while i < bytes.count {
            let start = i
            let tag = bytes[i]; i += 1
            guard i < bytes.count else { return out }
            var len = Int(bytes[i]); i += 1
            if len & 0x80 != 0 {
                let n = len & 0x7F
                guard n > 0, n <= 4, i + n <= bytes.count else { return out }
                len = 0
                for _ in 0..<n { len = (len << 8) | Int(bytes[i]); i += 1 }
            }
            guard len >= 0, i + len <= bytes.count else { return out }
            out.append(ASN1Node(tag: tag, value: Array(bytes[i..<(i + len)]), raw: Array(bytes[start..<(i + len)])))
            i += len
        }
        return out
    }

    static func oid(_ bytes: [UInt8]) -> String {
        guard let first = bytes.first else { return "" }
        var parts = [Int(first) / 40, Int(first) % 40]
        var acc = 0
        for b in bytes.dropFirst() {
            acc = (acc << 7) | Int(b & 0x7F)
            if b & 0x80 == 0 { parts.append(acc); acc = 0 }
        }
        return parts.map(String.init).joined(separator: ".")
    }

    static func string(_ n: ASN1Node) -> String {
        let d = Data(n.value)
        switch n.tag {
        case 0x1E: return String(data: d, encoding: .utf16BigEndian) ?? ""
        case 0x0C: return String(data: d, encoding: .utf8) ?? ""
        default: return String(data: d, encoding: .utf8) ?? String(data: d, encoding: .isoLatin1) ?? ""
        }
    }

    static func time(_ n: ASN1Node) -> Date? {
        guard let s = String(bytes: n.value, encoding: .ascii) else { return nil }
        var digits = s.hasSuffix("Z") ? String(s.dropLast()) : s
        var year: Int
        if n.tag == 0x17 {              // UTCTime YYMMDDHHMM[SS]
            guard digits.count >= 10, let yy = Int(digits.prefix(2)) else { return nil }
            year = yy < 50 ? 2000 + yy : 1900 + yy
            digits = String(digits.dropFirst(2))
        } else {                        // GeneralizedTime YYYYMMDDHHMM[SS]
            guard digits.count >= 12, let yyyy = Int(digits.prefix(4)) else { return nil }
            year = yyyy
            digits = String(digits.dropFirst(4))
        }
        let nums = stride(from: 0, to: digits.count - 1, by: 2).compactMap { i -> Int? in
            let a = digits.index(digits.startIndex, offsetBy: i)
            return Int(digits[a..<digits.index(a, offsetBy: 2)])
        }
        guard nums.count >= 4 else { return nil }
        var c = DateComponents()
        c.year = year; c.month = nums[0]; c.day = nums[1]; c.hour = nums[2]; c.minute = nums[3]
        c.second = nums.count > 4 ? nums[4] : 0
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal.date(from: c)
    }
}

// MARK: - Certificate model

public struct X509Info: Codable, Hashable, Sendable {
    public var subject: String
    public var subjectCN: String
    public var issuer: String
    public var issuerCN: String
    public var serialHex: String
    public var notBefore: Date
    public var notAfter: Date
    public var signatureAlgorithm: String
    public var keyAlgorithm: String
    public var keyBits: Int?
    public var subjectAltNames: [String]
    public var isCA: Bool
    public var selfSigned: Bool
    public var version: Int
    public var sha256: String
    public var sha1: String

    public var daysRemaining: Int { Int((notAfter.timeIntervalSinceNow / 86400).rounded(.down)) }
    public var isExpired: Bool { notAfter < Date() }
    public var isNotYetValid: Bool { notBefore > Date() }
    public var validityDays: Int { Int((notAfter.timeIntervalSince(notBefore) / 86400).rounded()) }
}

public enum X509 {
    static let attrNames: [String: String] = [
        "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
        "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress", "2.5.4.9": "street", "2.5.4.15": "businessCategory"
    ]
    static let sigAlgs: [String: String] = [
        "1.2.840.113549.1.1.4": "md5WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA",
        "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.12": "sha384WithRSA",
        "1.2.840.113549.1.1.13": "sha512WithRSA", "1.2.840.113549.1.1.10": "RSASSA-PSS",
        "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
        "1.3.101.112": "Ed25519"
    ]
    static let curves: [String: (String, Int)] = [
        "1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384), "1.3.132.0.35": ("P-521", 521)
    ]

    static func name(_ n: ASN1Node) -> (full: String, cn: String) {
        var parts: [String] = []
        var cn = ""
        for rdn in n.children {
            for atv in rdn.children {
                let kids = atv.children
                guard kids.count == 2 else { continue }
                let key = ASN1.oid(kids[0].value)
                let label = attrNames[key] ?? key
                let val = ASN1.string(kids[1])
                parts.append("\(label)=\(val)")
                if label == "CN", cn.isEmpty { cn = val }
            }
        }
        return (parts.joined(separator: ", "), cn)
    }

    public static func parse(der: Data) -> X509Info? {
        let bytes = [UInt8](der)
        guard let cert = ASN1.parse(bytes).first, cert.tag == 0x30 else { return nil }
        let top = cert.children
        guard top.count >= 3, top[0].tag == 0x30 else { return nil }
        var f = top[0].children
        var version = 1
        if let first = f.first, first.tag == 0xA0 {
            version = (first.children.first?.value.last.map(Int.init) ?? 0) + 1
            f.removeFirst()
        }
        guard f.count >= 6 else { return nil }
        let serial = f[0].value.drop(while: { $0 == 0 }).map { String(format: "%02X", $0) }.joined(separator: ":")
        let sigAlgOID = ASN1.oid(f[1].children.first?.value ?? [])
        let issuerNode = f[2], validity = f[3].children, subjectNode = f[4], spki = f[5]
        guard validity.count == 2, let nb = ASN1.time(validity[0]), let na = ASN1.time(validity[1]) else { return nil }

        let issuer = name(issuerNode), subject = name(subjectNode)

        // Public key
        var keyAlg = "unknown"
        var keyBits: Int?
        let spkiKids = spki.children
        if spkiKids.count == 2 {
            let alg = spkiKids[0].children
            let algOID = ASN1.oid(alg.first?.value ?? [])
            let bitString = Array(spkiKids[1].value.dropFirst())     // drop "unused bits" byte
            switch algOID {
            case "1.2.840.113549.1.1.1":
                keyAlg = "RSA"
                if let seq = ASN1.parse(bitString).first, let modulus = seq.children.first {
                    let m = Array(modulus.value.drop(while: { $0 == 0 }))
                    if let lead = m.first {
                        keyBits = (m.count - 1) * 8 + (8 - lead.leadingZeroBitCount)
                    }
                }
            case "1.2.840.10045.2.1":
                keyAlg = "EC"
                if alg.count > 1, let c = curves[ASN1.oid(alg[1].value)] { keyAlg = "EC \(c.0)"; keyBits = c.1 }
            case "1.3.101.112": keyAlg = "Ed25519"; keyBits = 256
            default: keyAlg = algOID
            }
        }

        // Extensions
        var sans: [String] = []
        var isCA = false
        if let extWrap = f.dropFirst(6).first(where: { $0.tag == 0xA3 }), let extSeq = extWrap.children.first {
            for ext in extSeq.children {
                let kids = ext.children
                guard kids.count >= 2, let valueNode = kids.last else { continue }
                let oid = ASN1.oid(kids[0].value)
                let inner = ASN1.parse(valueNode.value).first
                if oid == "2.5.29.17", let seq = inner {
                    for gn in seq.children {
                        switch gn.tag {
                        case 0x82: sans.append(String(bytes: gn.value, encoding: .utf8) ?? "")
                        case 0x81: sans.append("email:" + (String(bytes: gn.value, encoding: .utf8) ?? ""))
                        case 0x86: sans.append("uri:" + (String(bytes: gn.value, encoding: .utf8) ?? ""))
                        case 0x87:
                            if gn.value.count == 4 { sans.append(gn.value.map(String.init).joined(separator: ".")) }
                            else if gn.value.count == 16 {
                                sans.append(stride(from: 0, to: 16, by: 2).map { String(format: "%x", Int(gn.value[$0]) << 8 | Int(gn.value[$0 + 1])) }.joined(separator: ":"))
                            }
                        default: break
                        }
                    }
                } else if oid == "2.5.29.19", let seq = inner {
                    if let b = seq.children.first, b.tag == 0x01, let v = b.value.first { isCA = v != 0 }
                }
            }
        }

        return X509Info(
            subject: subject.full, subjectCN: subject.cn, issuer: issuer.full, issuerCN: issuer.cn,
            serialHex: serial, notBefore: nb, notAfter: na,
            signatureAlgorithm: sigAlgs[sigAlgOID] ?? sigAlgOID,
            keyAlgorithm: keyAlg, keyBits: keyBits, subjectAltNames: sans, isCA: isCA,
            selfSigned: issuerNode.raw == subjectNode.raw, version: version,
            sha256: Digests.hex(.sha256, der) ?? "", sha1: Digests.hex(.sha1, der) ?? "")
    }

    /// RFC 6125-style match supporting a single left-most wildcard label.
    public static func hostMatches(_ host: String, names: [String]) -> Bool {
        let h = host.lowercased()
        for raw in names {
            let n = raw.lowercased()
            if n == h { return true }
            if n.hasPrefix("*.") {
                let suffix = String(n.dropFirst(1))               // ".example.com"
                if h.hasSuffix(suffix), h.dropLast(suffix.count).split(separator: ".").count == 1 { return true }
            }
        }
        return false
    }
}
