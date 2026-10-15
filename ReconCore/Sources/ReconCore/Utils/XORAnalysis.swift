import Foundation

/// Repeating-key (Vigenère-on-bytes) XOR breaking and two-time-pad crib dragging — the classic
/// cryptopals-style attacks. Pure and unit-tested.
public enum XORAnalysis {

    static func bytes(from input: String) -> [UInt8] {
        if let d = Encoders.hexDecode(input) { return [UInt8](d) }
        if let d = Encoders.base64Decode(input), !d.isEmpty { return [UInt8](d) }
        return [UInt8](Data(input.utf8))
    }

    public static func hamming(_ a: [UInt8], _ b: [UInt8]) -> Int {
        zip(a, b).reduce(0) { $0 + ($1.0 ^ $1.1).nonzeroBitCount }
    }

    /// Likely key sizes, ranked by the normalised Hamming distance between adjacent blocks.
    public static func likelyKeySizes(_ data: [UInt8], max: Int = 40) -> [Int] {
        var scores: [(Int, Double)] = []
        for ks in 2...Swift.min(max, data.count / 4) {
            let blocks = Swift.min(6, data.count / ks - 1)
            guard blocks >= 1 else { continue }
            var total = 0.0
            for i in 0..<blocks {
                let a = Array(data[i * ks ..< (i + 1) * ks])
                let b = Array(data[(i + 1) * ks ..< (i + 2) * ks])
                total += Double(hamming(a, b)) / Double(ks)
            }
            scores.append((ks, total / Double(blocks)))
        }
        return scores.sorted { $0.1 < $1.1 }.prefix(4).map { $0.0 }
    }

    static func bestByte(for column: [UInt8]) -> UInt8 {
        var best: UInt8 = 0
        var bestScore = -Double.greatestFiniteMagnitude
        for k in 0...255 {
            let x = column.map { $0 ^ UInt8(k) }
            let s = CTFScore.english(Data(x))
            if s > bestScore { bestScore = s; best = UInt8(k) }
        }
        return best
    }

    public static func breakRepeatingKey(_ data: [UInt8]) -> (key: [UInt8], plaintext: [UInt8])? {
        guard data.count >= 8 else { return nil }
        var best: (key: [UInt8], score: Double, text: [UInt8])?
        for ks in likelyKeySizes(data) {
            var key: [UInt8] = []
            for col in 0..<ks {
                var column: [UInt8] = []
                var i = col; while i < data.count { column.append(data[i]); i += ks }
                key.append(bestByte(for: column))
            }
            let pt = data.enumerated().map { $0.element ^ key[$0.offset % ks] }
            let score = CTFScore.english(Data(pt))
            if best == nil || score > best!.score { best = (key, score, pt) }
        }
        guard let r = best else { return nil }
        return (r.key, r.text)
    }

    public static func runRepeatingKey(_ input: String) -> ToolOutput {
        let data = bytes(from: input.trimmed())
        var out = ToolOutput()
        guard let (key, pt) = breakRepeatingKey(data) else {
            return ToolOutput(sections: [ReportSection("Repeating-key XOR", items: [ReportItem("Error", "need at least 8 bytes", .low)])])
        }
        let text = String(bytes: pt, encoding: .utf8) ?? String(bytes: pt, encoding: .isoLatin1) ?? ""
        var s = ReportSection("Repeating-key XOR break",
                              note: "Key size found by normalised Hamming distance; each column solved as single-byte XOR.")
        let keyAscii = String(bytes: key, encoding: .utf8).map { $0.allSatisfy { $0.isLetter || $0.isNumber || $0.isPunctuation || $0 == " " } ? $0 : "" } ?? ""
        s.add("Key length", "\(key.count)")
        s.add("Key (hex)", key.map { String(format: "%02x", $0) }.joined())
        if !keyAscii.isEmpty { s.add("Key (ascii)", keyAscii) }
        s.add("Plaintext", text, FlagHunter.find(in: text).isEmpty ? .info : .high)
        for f in FlagHunter.find(in: text) { out.findings.append(Finding(.high, "Possible flag: \(f)", "repeating-key XOR", source: "ctf")) }
        out.sections = [s]
        return out
    }

    // MARK: Two-time-pad crib dragging

    /// For two ciphertexts sharing a key, dragging a known crib across c1⊕c2 reveals the other message.
    public static func cribDrag(_ c1: [UInt8], _ c2: [UInt8], crib: String) -> [(offset: Int, text: String)] {
        let x = zip(c1, c2).map { $0 ^ $1 }
        let cb = [UInt8](crib.utf8)
        guard !cb.isEmpty, x.count >= cb.count else { return [] }
        var out: [(Int, String)] = []
        for off in 0...(x.count - cb.count) {
            let frag = (0..<cb.count).map { x[off + $0] ^ cb[$0] }
            if frag.allSatisfy({ ($0 >= 32 && $0 < 127) || $0 == 10 }) {
                out.append((off, String(bytes: frag, encoding: .utf8) ?? ""))
            }
        }
        return out
    }

    public static func runCribDrag(_ input: String) -> ToolOutput {
        // Format: two hex ciphertext lines; optional "::crib words" for the cribs to try.
        let parts = input.components(separatedBy: "::")
        let lines = parts[0].split(whereSeparator: { $0 == "\n" }).map { String($0).trimmed() }.filter { !$0.isEmpty }
        guard lines.count >= 2, let c1 = Encoders.hexDecode(lines[0]), let c2 = Encoders.hexDecode(lines[1]) else {
            return ToolOutput(sections: [ReportSection("XOR crib drag", items: [
                ReportItem("Usage", "two hex ciphertexts (same key), one per line; optional ::the of and flag{", .low)])])
        }
        let cribs = parts.count > 1 ? parts[1].split(whereSeparator: { $0 == " " || $0 == "," }).map(String.init)
                                    : [" the ", " and ", " of ", " that ", "flag{", "The ", " to "]
        var out = ToolOutput()
        var s = ReportSection("XOR crib drag",
                              note: "c1⊕c2 = m1⊕m2. A guessed word slid across it reveals the other message where it lines up.")
        var any = false
        for crib in cribs {
            let hits = cribDrag([UInt8](c1), [UInt8](c2), crib: crib).filter { $0.text.trimmed().count >= crib.trimmed().count }
            for h in hits.prefix(6) where h.text.contains(where: { $0.isLetter }) {
                s.add("“\(crib)” @ \(h.offset)", "→ \(h.text)")
                any = true
            }
        }
        if !any { s.add("Result", "no readable fragments. Try different cribs via ::word1 word2", .low) }
        out.sections = [s]
        return out
    }
}
