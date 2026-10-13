import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Offline brute-force of HMAC-signed JWTs (HS256/384/512) against a built-in weak-secret list,
/// plus any extra candidates the user supplies. Verifies the real signature — no false positives.
public enum JWTCrack {

    static func mac(alg: String, key: [UInt8], message: [UInt8]) -> [UInt8]? {
        switch alg.uppercased() {
        case "HS256":
            #if canImport(CryptoKit)
            return Array(HMAC<SHA256>.authenticationCode(for: Data(message), using: SymmetricKey(data: Data(key))))
            #else
            return PureHash.hmac(key: key, message: message, hash: PureHash.sha256)
            #endif
        case "HS384":
            #if canImport(CryptoKit)
            return Array(HMAC<SHA384>.authenticationCode(for: Data(message), using: SymmetricKey(data: Data(key))))
            #else
            return nil
            #endif
        case "HS512":
            #if canImport(CryptoKit)
            return Array(HMAC<SHA512>.authenticationCode(for: Data(message), using: SymmetricKey(data: Data(key))))
            #else
            return nil
            #endif
        default: return nil
        }
    }

    static func base64url(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Returns the secret if one in `candidates` verifies the signature.
    public static func crack(token: String, candidates: [String]) -> (alg: String, secret: String?)? {
        let parts = token.trimmed().split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else { return nil }
        guard let hdrData = Encoders.base64Decode(parts[0]),
              let hdr = try? JSONSerialization.jsonObject(with: hdrData) as? [String: Any],
              let alg = hdr["alg"] as? String else { return nil }
        let signingInput = Array("\(parts[0]).\(parts[1])".utf8)
        let given = parts[2]
        for secret in candidates {
            guard let m = mac(alg: alg, key: Array(secret.utf8), message: signingInput) else { return (alg, nil) }
            if base64url(m) == given { return (alg, secret) }
        }
        return (alg, nil)
    }

    public static func run(_ input: String) -> ToolOutput {
        // Accept "token" or "token :: extraword1 extraword2" to add custom candidates.
        let pieces = input.components(separatedBy: "::")
        let token = pieces[0].trimmed()
        var list = weakSecrets
        if pieces.count > 1 {
            list = pieces[1].split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "," }).map(String.init) + list
        }
        var out = ToolOutput()
        // Always show the decoded token first.
        out.merge(JWT.analyze(token))

        guard let result = crack(token: token, candidates: list) else {
            out.sections.append(ReportSection("Secret cracking", items: [ReportItem("Error", "not a valid 3-part JWT", .low)]))
            return out
        }
        var s = ReportSection("Secret cracking", note: "Tried \(list.count) candidates against the real HMAC signature.")
        if !result.alg.uppercased().hasPrefix("HS") {
            s.add("Algorithm", "\(result.alg) — asymmetric, not brute-forceable (needs the private key)", .info)
        } else if mac(alg: result.alg, key: [0], message: [0]) == nil {
            s.add("Algorithm", "\(result.alg) — unsupported on this platform build", .low)
        } else if let secret = result.secret {
            s.add("CRACKED", "secret = \"\(secret)\"", .critical)
            out.findings.append(Finding(.critical, "JWT signed with weak secret: \"\(secret)\"",
                                        "The token can be forged. Rotate the signing key to a long random value.", source: "jwt"))
        } else {
            s.add("Result", "no match in \(list.count) candidates — try a larger wordlist with '::'", .info)
        }
        out.sections.append(s)
        return out
    }

    /// A compact list of secrets that repeatedly show up in misconfigured apps and CTF challenges.
    public static let weakSecrets: [String] = [
        "secret", "secretkey", "secret_key", "secretKey", "jwt", "jwtsecret", "jwt_secret", "jwtSecret",
        "password", "pass", "passwd", "123456", "12345678", "admin", "administrator", "root", "test",
        "changeme", "default", "key", "private", "privatekey", "token", "auth", "authsecret", "supersecret",
        "super_secret", "mysecret", "my_secret", "topsecret", "qwerty", "letmein", "welcome", "iloveyou",
        "abc123", "p@ssw0rd", "Password1", "s3cr3t", "secret123", "example", "hello", "world", "foo", "bar",
        "foobar", "none", "null", "undefined", "development", "dev", "production", "prod", "staging", "local",
        "application", "app", "node", "express", "flask", "django", "laravel", "symfony", "spring", "api",
        "apikey", "api_key", "access", "accesstoken", "access_token", "refresh", "refreshtoken", "session",
        "sessionkey", "signature", "sign", "hmac", "sha256", "0000", "1111", "123123", "password123",
        "your-256-bit-secret", "your_jwt_secret", "my-secret-key", "keyboard cat", "shhhh", "secretpassword",
        "P@ssword", "Admin123", "letmein123", "test123", "demo", "guest", "oauth", "bearer", "jsonwebtoken",
        "HS256", "verysecret", "ultrasecret", "donttell", "nobodyknows", "0123456789", "a", "aaaa",
        "the quick brown fox", "CTFsecret", "flag", "ctf", "pentest", "redteam", "blueteam", "secret1",
        "Password123!", "Welcome1", "qazwsx", "zxcvbnm", "master", "login", "user", "users", "backend"
    ]
}
