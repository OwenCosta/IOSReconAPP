import Foundation

/// Dictionary attack on unsalted MD5 / SHA-1 / SHA-256 hashes, using the built-in word lists plus
/// common numeric PINs and any extra candidates the user supplies. Uses the portable hashing core.
public enum HashCracker {
    static func kind(forLength n: Int) -> DigestKind? {
        switch n {
        case 32: return .md5
        case 40: return .sha1
        case 64: return .sha256
        default: return nil
        }
    }

    public static func wordlist(extra: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        func add(_ w: String) { if seen.insert(w).inserted { out.append(w) } }
        extra.forEach(add)
        JWTCrack.weakSecrets.forEach(add)
        SubstitutionSolver.corpusWords.forEach(add)
        // A few common mutations of each base word.
        for base in Array(out) {
            add(base + "1"); add(base + "123"); add(base + "!"); add(base.capitalized)
        }
        return out
    }

    /// Returns the cracked plaintext, or nil. Also tries numeric PINs up to `maxPIN`.
    public static func crack(_ hashHex: String, kind: DigestKind, extra: [String] = [], maxPIN: Int = 100_000) -> String? {
        let target = hashHex.trimmed().lowercased()
        for w in wordlist(extra: extra) {
            if Digests.hex(kind, w)?.lowercased() == target { return w }
        }
        for n in 0..<maxPIN {
            let candidate = String(n)
            if Digests.hex(kind, candidate)?.lowercased() == target { return candidate }
            // zero-padded PINs (0001 etc.) for 3–6 digit spaces
            if n < 1_000_000 {
                for width in [4, 6] where String(n).count < width {
                    let padded = String(repeating: "0", count: width - String(n).count) + String(n)
                    if Digests.hex(kind, padded)?.lowercased() == target { return padded }
                }
            }
        }
        return nil
    }

    public static func run(_ input: String) -> ToolOutput {
        let parts = input.components(separatedBy: "::")
        let hash = parts[0].trimmed()
        let extra = parts.count > 1 ? parts[1].split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "," }).map(String.init) : []
        var out = ToolOutput()
        var s = ReportSection("Hash cracker", note: "Dictionary + common-PIN attack on unsalted MD5/SHA-1/SHA-256. Add words with ::word1 word2.")
        guard hash.allSatisfy({ $0.isHexDigit }), let kind = kind(forLength: hash.count) else {
            s.add("Error", "paste a 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex-char hash", .low)
            out.sections = [s]; return out
        }
        s.add("Detected", kind.rawValue)
        // keep the PIN space small when extra words are the point; still covers 4–5 digit PINs fast
        if let plain = crack(hash, kind: kind, extra: extra, maxPIN: 100_000) {
            s.add("CRACKED", "\"\(plain)\"", .critical)
            out.findings.append(Finding(.critical, "\(kind.rawValue) hash cracked: \"\(plain)\"", source: "ctf"))
        } else {
            s.add("Result", "not found in the built-in dictionary or PIN space — add a wordlist via ::", .info)
        }
        out.sections = [s]
        return out
    }
}
