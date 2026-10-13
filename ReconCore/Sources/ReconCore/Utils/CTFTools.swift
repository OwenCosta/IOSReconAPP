import Foundation

// MARK: - Shared scoring & flag detection

enum CTFScore {
    /// Fraction of bytes that are printable ASCII (incl. common whitespace).
    static func printable(_ d: Data) -> Double {
        guard !d.isEmpty else { return 0 }
        var ok = 0
        for b in d {
            if b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127) { ok += 1 }
        }
        return Double(ok) / Double(d.count)
    }

    /// Rough "looks like English/plaintext" score: rewards letters, spaces and common bytes.
    static func english(_ d: Data) -> Double {
        guard !d.isEmpty else { return 0 }
        let freq: [UInt8: Double] = [32: 13, 101: 12.7, 116: 9.1, 97: 8.2, 111: 7.5, 105: 7, 110: 6.7,
                                     115: 6.3, 104: 6.1, 114: 6, 108: 4, 100: 4.3, 99: 2.8, 117: 2.8]
        var score = 0.0
        for b in d {
            let lower = (b >= 65 && b <= 90) ? b + 32 : b
            if let w = freq[lower] { score += w }
            else if lower >= 97 && lower <= 122 { score += 1 }
            else if b >= 32 && b < 127 { score += 0.3 }
            else if b == 9 || b == 10 || b == 13 { score += 0.1 }
            else { score -= 5 }   // penalise non-printable
        }
        return score / Double(d.count)
    }

    static func text(_ d: Data) -> String? {
        String(data: d, encoding: .utf8) ?? String(data: d, encoding: .isoLatin1)
    }
}

/// Finds CTF-style flags like `flag{...}`, `CTF{...}`, `picoCTF{...}`, `HTB{...}`.
public enum FlagHunter {
    static let pattern = #"[A-Za-z0-9_][A-Za-z0-9_\-]{1,24}\{[^}\r\n]{1,256}\}"#

    public static func find(in text: String) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        var out: [String] = []
        var seen = Set<String>()
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let s = ns.substring(with: m.range)
            if seen.insert(s).inserted { out.append(s) }
        }
        return out
    }

    public static func run(_ input: String) -> ToolOutput {
        var out = ToolOutput()
        let flags = find(in: input)
        var s = ReportSection("Flag candidates (\(flags.count))",
                              note: "Matches NAME{...} patterns (flag{}, CTF{}, picoCTF{}, HTB{} …).")
        if flags.isEmpty {
            s.add("Result", "no flag pattern found in \(input.count) chars", .low)
        } else {
            for f in flags {
                s.add("flag", f, .high)
                out.findings.append(Finding(.high, "Possible flag: \(f)", source: "ctf"))
            }
        }
        out.sections = [s]
        return out
    }
}

// MARK: - Extra encoders (Base32, binary, decimal bytes)

enum CTFEncoders {
    static func base32Decode(_ s: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var lookup: [Character: Int] = [:]
        for (i, c) in alphabet.enumerated() { lookup[c] = i }
        let clean = s.uppercased().filter { !$0.isWhitespace && $0 != "=" }
        guard clean.count >= 2 else { return nil }
        var bits = 0, value = 0
        var out: [UInt8] = []
        for c in clean {
            guard let v = lookup[c] else { return nil }
            value = (value << 5) | v
            bits += 5
            if bits >= 8 { bits -= 8; out.append(UInt8((value >> bits) & 0xFF)) }
        }
        return out.isEmpty ? nil : Data(out)
    }

    /// "01001000 01101001" or "0100100001101001" → "Hi"
    static func fromBinary(_ s: String) -> Data? {
        let bitsOnly = s.filter { $0 == "0" || $0 == "1" }
        guard bitsOnly.count >= 8, bitsOnly.count % 8 == 0 else { return nil }
        var out: [UInt8] = []
        let chars = Array(bitsOnly)
        var i = 0
        while i < chars.count {
            let byte = String(chars[i..<i+8])
            guard let v = UInt8(byte, radix: 2) else { return nil }
            out.append(v); i += 8
        }
        return Data(out)
    }

    /// "72 105 33" → "Hi!"
    static func fromDecimalBytes(_ s: String) -> Data? {
        let parts = s.split(whereSeparator: { $0 == " " || $0 == "," || $0 == "\n" || $0 == "\t" })
        guard parts.count >= 2 else { return nil }
        var out: [UInt8] = []
        for p in parts {
            guard let n = Int(p), (0...255).contains(n) else { return nil }
            out.append(UInt8(n))
        }
        return Data(out)
    }

    /// Bitcoin/IPFS Base58.
    static let b58 = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    static func base58Decode(_ s: String) -> Data? {
        let clean = s.trimmed()
        guard clean.count >= 2 else { return nil }
        var lookup: [Character: Int] = [:]
        for (i, c) in b58.enumerated() { lookup[c] = i }
        var bytes: [UInt8] = [0]
        for ch in clean {
            guard let v = lookup[ch] else { return nil }
            var carry = v
            for i in 0..<bytes.count { carry += Int(bytes[i]) * 58; bytes[i] = UInt8(carry & 0xff); carry >>= 8 }
            while carry > 0 { bytes.append(UInt8(carry & 0xff)); carry >>= 8 }
        }
        for ch in clean { if ch == "1" { bytes.append(0) } else { break } }
        return Data(bytes.reversed())
    }

    /// Ascii85 / Base85 (Adobe variant, optional <~ ~> wrapper).
    static func ascii85Decode(_ s: String) -> Data? {
        var t = s.trimmed()
        if t.hasPrefix("<~") { t = String(t.dropFirst(2)) }
        if t.hasSuffix("~>") { t = String(t.dropLast(2)) }
        t = t.filter { !$0.isWhitespace }
        guard !t.isEmpty else { return nil }
        var out: [UInt8] = []
        var group: [UInt8] = []
        func flush(_ g: [UInt8]) -> Bool {
            guard !g.isEmpty else { return true }
            var padded = g
            while padded.count < 5 { padded.append(84) }   // 'u'
            var value: UInt32 = 0
            for c in padded {
                guard c >= 0 && c <= 84 else { return false }
                value = value &* 85 &+ UInt32(c)
            }
            let bytes = [UInt8(value >> 24 & 0xff), UInt8(value >> 16 & 0xff), UInt8(value >> 8 & 0xff), UInt8(value & 0xff)]
            out.append(contentsOf: bytes.prefix(g.count - 1))
            return true
        }
        for ch in t.unicodeScalars {
            if ch == "z" && group.isEmpty { out.append(contentsOf: [0, 0, 0, 0]); continue }
            guard ch.value >= 33 && ch.value <= 117 else { return nil }
            group.append(UInt8(ch.value - 33))
            if group.count == 5 { if !flush(group) { return nil }; group = [] }
        }
        if !flush(group) { return nil }
        return out.isEmpty ? nil : Data(out)
    }

    static let morseMap: [String: Character] = [
        ".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J",
        "-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T",
        "..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z",
        "-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7",
        "---..":"8","----.":"9",".-.-.-":".","--..--":",","..--..":"?","-..-.":"/","-....-":"-","-.--.":"(","-.--.-":")"]

    /// ".... ..  ..-. .-.. .- --." with "/" or double-space between words.
    static func morseDecode(_ s: String) -> String? {
        let normalized = s.replacingOccurrences(of: "/", with: "   ")
        let isMorse = s.allSatisfy { ".-/ \n\t".contains($0) } && s.contains(where: { $0 == "." || $0 == "-" })
        guard isMorse else { return nil }
        var out = ""
        for word in normalized.components(separatedBy: "   ") where !word.trimmed().isEmpty {
            for letter in word.split(separator: " ") {
                if let c = morseMap[String(letter)] { out.append(c) } else { out.append("?") }
            }
            out.append(" ")
        }
        let result = out.trimmed()
        return result.isEmpty ? nil : result
    }
}

// MARK: - Magic recursive decoder

/// Breadth-first "cyberchef magic": repeatedly tries encodings until it finds a flag or clean text.
public enum MagicDecoder {
    struct Transform { let name: String; let apply: (String) -> String? }

    static let transforms: [Transform] = [
        Transform(name: "Base64") { s in Encoders.base64Decode(s).flatMap(printableText) },
        Transform(name: "Base32") { s in CTFEncoders.base32Decode(s).flatMap(printableText) },
        Transform(name: "Hex") { s in Encoders.hexDecode(s).flatMap(printableText) },
        Transform(name: "Binary") { s in CTFEncoders.fromBinary(s).flatMap(printableText) },
        Transform(name: "Decimal bytes") { s in CTFEncoders.fromDecimalBytes(s).flatMap(printableText) },
        Transform(name: "Base58") { s in CTFEncoders.base58Decode(s).flatMap(printableText) },
        Transform(name: "Ascii85") { s in CTFEncoders.ascii85Decode(s).flatMap(printableText) },
        Transform(name: "Morse") { s in CTFEncoders.morseDecode(s) },
        Transform(name: "URL-decode") { s in
            guard let d = s.removingPercentEncoding, d != s else { return nil }; return d },
        Transform(name: "ROT13") { s in lettersMostly(s) ? Encoders.rot13(s) : nil },
        Transform(name: "Reverse") { s in lettersMostly(s) ? String(s.reversed()) : nil }
    ]

    static func printableText(_ d: Data) -> String? {
        guard CTFScore.printable(d) >= 0.9, let t = CTFScore.text(d), !t.isEmpty else { return nil }
        return t
    }
    static func lettersMostly(_ s: String) -> Bool {
        let letters = s.filter { $0.isLetter }.count
        return s.count >= 3 && Double(letters) / Double(s.count) > 0.6
    }

    public struct Hit { public let chain: [String]; public let output: String; public let flags: [String] }

    public static func solve(_ input: String, maxDepth: Int = 6, maxNodes: Int = 600) -> [Hit] {
        var hits: [Hit] = []
        var visited = Set<String>([input])
        var queue: [(text: String, chain: [String])] = [(input, [])]
        var nodes = 0

        while !queue.isEmpty && nodes < maxNodes {
            let (text, chain) = queue.removeFirst()
            if chain.count >= maxDepth { continue }
            for t in transforms {
                guard let next = t.apply(text), next != text, !visited.contains(next) else { continue }
                nodes += 1
                visited.insert(next)
                let newChain = chain + [t.name]
                let flags = FlagHunter.find(in: next)
                if !flags.isEmpty {
                    hits.append(Hit(chain: newChain, output: next, flags: flags))
                }
                if next.count <= 4096 { queue.append((next, newChain)) }
            }
        }
        // If no flag found, surface the most "English-looking" leaf as a best guess.
        if hits.isEmpty {
            var best: Hit?
            var bestScore = CTFScore.english(Data(input.utf8))
            visited.remove(input)
            for v in visited {
                let sc = CTFScore.english(Data(v.utf8))
                if sc > bestScore + 0.5 { bestScore = sc; best = Hit(chain: ["(best guess)"], output: v, flags: []) }
            }
            if let b = best { hits.append(b) }
        }
        return Array(hits.prefix(12))
    }

    public static func run(_ input: String) -> ToolOutput {
        let text = input.trimmed()
        guard !text.isEmpty else { return ToolOutput(sections: [ReportSection("Magic decode", items: [ReportItem("Error", "empty input", .low)])]) }
        var out = ToolOutput()
        let hits = solve(text)
        var s = ReportSection("Magic decode", note: "Recursively tries Base64/32, hex, binary, decimal, URL, ROT13 and reverse.")
        if hits.isEmpty {
            s.add("Result", "nothing decoded — input may already be plaintext or an unsupported format", .low)
        }
        for (i, h) in hits.enumerated() {
            let label = h.chain.joined(separator: " → ")
            s.add("\(i + 1). \(label)", h.output, h.flags.isEmpty ? .info : .high)
            for f in h.flags { out.findings.append(Finding(.high, "Possible flag: \(f)", "via \(label)", source: "ctf")) }
        }
        out.sections = [s]
        return out
    }
}

// MARK: - XOR single-byte brute force

public enum XORTools {
    /// Accepts hex (preferred) or raw text. Brute-forces every single-byte key.
    public static func singleByteBrute(_ input: String) -> ToolOutput {
        let bytes: [UInt8]
        if let d = Encoders.hexDecode(input) { bytes = [UInt8](d) }
        else { bytes = [UInt8](Data(input.utf8)) }
        guard !bytes.isEmpty else { return ToolOutput(sections: [ReportSection("XOR", items: [ReportItem("Error", "empty input", .low)])]) }

        var scored: [(key: UInt8, score: Double, text: String, flags: [String])] = []
        for key in 0...255 {
            let k = UInt8(key)
            let xored = Data(bytes.map { $0 ^ k })
            let score = CTFScore.english(xored)
            let text = CTFScore.text(xored) ?? ""
            scored.append((k, score, text, FlagHunter.find(in: text)))
        }
        scored.sort { $0.score > $1.score }

        func keyDesc(_ k: UInt8) -> String {
            String(format: "0x%02X (%d%@)", k, k, (k >= 33 && k < 127) ? " '\(Character(UnicodeScalar(k)))'" : "")
        }
        var out = ToolOutput()
        var s = ReportSection("Single-byte XOR — top candidates",
                              note: "Tried all 256 keys on \(bytes.count) bytes, ranked by English-likeness.")
        // Any key that reveals a flag is reported, even if its English score is low.
        var shown = Set<UInt8>()
        for cand in scored where !cand.flags.isEmpty {
            let preview = cand.text.replacingOccurrences(of: "\n", with: " ").prefix(100)
            s.add("key \(keyDesc(cand.key))", String(preview), .high)
            shown.insert(cand.key)
            for f in cand.flags { out.findings.append(Finding(.high, "Possible flag: \(f)", "single-byte XOR key \(keyDesc(cand.key))", source: "ctf")) }
        }
        for cand in scored.prefix(10) where !shown.contains(cand.key) {
            let preview = cand.text.replacingOccurrences(of: "\n", with: " ").prefix(100)
            s.add("key \(keyDesc(cand.key))", String(preview), .info)
        }
        out.sections = [s]
        return out
    }
}

// MARK: - Classic rotation ciphers

public enum ClassicCipher {
    static func caesar(_ s: String, shift: Int) -> String {
        String(s.unicodeScalars.map { u -> Character in
            switch u.value {
            case 65...90: return Character(UnicodeScalar((u.value - 65 + UInt32((shift % 26 + 26) % 26)) % 26 + 65)!)
            case 97...122: return Character(UnicodeScalar((u.value - 97 + UInt32((shift % 26 + 26) % 26)) % 26 + 97)!)
            default: return Character(u)
            }
        })
    }

    static func atbash(_ s: String) -> String {
        String(s.unicodeScalars.map { u -> Character in
            switch u.value {
            case 65...90: return Character(UnicodeScalar(90 - (u.value - 65))!)
            case 97...122: return Character(UnicodeScalar(122 - (u.value - 97))!)
            default: return Character(u)
            }
        })
    }

    static func rot47(_ s: String) -> String {
        String(s.unicodeScalars.map { u -> Character in
            (u.value >= 33 && u.value <= 126) ? Character(UnicodeScalar(33 + (u.value - 33 + 47) % 94)!) : Character(u)
        })
    }

    public static func run(_ input: String) -> ToolOutput {
        let text = input.trimmed()
        var out = ToolOutput()
        var s = ReportSection("Caesar / ROT brute-force", note: "All 26 Caesar shifts plus Atbash and ROT47.")
        var best: (Int, Double) = (0, -1)
        for shift in 1...25 {
            let c = caesar(text, shift: shift)
            let sc = CTFScore.english(Data(c.utf8))
            if sc > best.1 { best = (shift, sc) }
            let flags = FlagHunter.find(in: c)
            s.add("ROT\(shift)", c.prefix(90).description, flags.isEmpty ? .info : .high)
            for f in flags { out.findings.append(Finding(.high, "Possible flag: \(f)", "Caesar shift \(shift)", source: "ctf")) }
        }
        let ab = atbash(text)
        s.add("Atbash", ab.prefix(90).description, FlagHunter.find(in: ab).isEmpty ? .info : .high)
        for f in FlagHunter.find(in: ab) { out.findings.append(Finding(.high, "Possible flag: \(f)", "Atbash", source: "ctf")) }
        let r47 = rot47(text)
        s.add("ROT47", r47.prefix(90).description, FlagHunter.find(in: r47).isEmpty ? .info : .high)
        for f in FlagHunter.find(in: r47) { out.findings.append(Finding(.high, "Possible flag: \(f)", "ROT47", source: "ctf")) }
        s.note = "All 26 Caesar shifts + Atbash + ROT47. Most English-like: ROT\(best.0)."
        out.sections = [s]
        return out
    }
}

// MARK: - Base / number converter

public enum NumberConverter {
    public static func run(_ input: String) -> ToolOutput {
        let t = input.trimmed()
        var s = ReportSection("Number / base conversion")
        // Try to parse a single integer with an optional base prefix.
        var intValue: UInt64?
        if t.hasPrefix("0x") || t.hasPrefix("0X") { intValue = UInt64(t.dropFirst(2), radix: 16) }
        else if t.hasPrefix("0b") || t.hasPrefix("0B") { intValue = UInt64(t.dropFirst(2), radix: 2) }
        else if t.hasPrefix("0o") || t.hasPrefix("0O") { intValue = UInt64(t.dropFirst(2), radix: 8) }
        else if let v = UInt64(t) { intValue = v }

        if let v = intValue {
            s.add("Decimal", "\(v)")
            s.add("Hex", "0x" + String(v, radix: 16))
            s.add("Octal", "0o" + String(v, radix: 8))
            s.add("Binary", "0b" + String(v, radix: 2))
            if v <= 0x10FFFF, let scalar = UnicodeScalar(UInt32(v)) { s.add("As character", "'\(Character(scalar))'") }
        } else {
            // Treat as ASCII text → show every representation.
            let bytes = [UInt8](Data(t.utf8))
            s.note = "Not a single number, so showing byte representations of the text."
            s.add("Hex", bytes.map { String(format: "%02x", $0) }.joined(separator: " "))
            s.add("Binary", bytes.map { String($0, radix: 2).leftPad(8) }.joined(separator: " "))
            s.add("Decimal", bytes.map { "\($0)" }.joined(separator: " "))
            s.add("Base64", Data(bytes).base64EncodedString())
        }
        return ToolOutput(sections: [s])
    }
}

private extension String {
    func leftPad(_ n: Int, _ c: Character = "0") -> String {
        count >= n ? self : String(repeating: c, count: n - count) + self
    }
}
