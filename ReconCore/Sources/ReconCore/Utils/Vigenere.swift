import Foundation

/// Vigenère cipher: decrypt with a known key, or recover the key automatically with
/// Index-of-Coincidence key-length detection + per-column chi-squared frequency analysis.
public enum Vigenere {
    // English letter frequencies (A–Z), as fractions.
    static let english: [Double] = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
                                    0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
                                    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
                                    0.01974, 0.00074]

    public static func decrypt(_ text: String, key: String) -> String {
        let keyNums = key.uppercased().unicodeScalars.filter { $0.value >= 65 && $0.value <= 90 }.map { Int($0.value) - 65 }
        guard !keyNums.isEmpty else { return text }
        var ki = 0
        var out = ""
        for ch in text.unicodeScalars {
            if ch.value >= 65 && ch.value <= 90 {
                out.unicodeScalars.append(UnicodeScalar(UInt32((Int(ch.value) - 65 - keyNums[ki % keyNums.count] + 26) % 26 + 65))!)
                ki += 1
            } else if ch.value >= 97 && ch.value <= 122 {
                out.unicodeScalars.append(UnicodeScalar(UInt32((Int(ch.value) - 97 - keyNums[ki % keyNums.count] + 26) % 26 + 97))!)
                ki += 1
            } else {
                out.unicodeScalars.append(ch)
            }
        }
        return out
    }

    public static func encrypt(_ text: String, key: String) -> String {
        let keyNums = key.uppercased().unicodeScalars.filter { $0.value >= 65 && $0.value <= 90 }.map { Int($0.value) - 65 }
        guard !keyNums.isEmpty else { return text }
        var ki = 0
        var out = ""
        for ch in text.unicodeScalars {
            if ch.value >= 65 && ch.value <= 90 {
                out.unicodeScalars.append(UnicodeScalar(UInt32((Int(ch.value) - 65 + keyNums[ki % keyNums.count]) % 26 + 65))!); ki += 1
            } else if ch.value >= 97 && ch.value <= 122 {
                out.unicodeScalars.append(UnicodeScalar(UInt32((Int(ch.value) - 97 + keyNums[ki % keyNums.count]) % 26 + 97))!); ki += 1
            } else {
                out.unicodeScalars.append(ch)
            }
        }
        return out
    }

    static func letters(_ s: String) -> [Int] {
        s.uppercased().unicodeScalars.filter { $0.value >= 65 && $0.value <= 90 }.map { Int($0.value) - 65 }
    }

    static func ic(_ nums: [Int]) -> Double {
        guard nums.count > 1 else { return 0 }
        var counts = [Int](repeating: 0, count: 26)
        for n in nums { counts[n] += 1 }
        let total = nums.count
        var sum = 0.0
        for c in counts { sum += Double(c * (c - 1)) }
        return sum / Double(total * (total - 1))
    }

    /// Average IC across the columns formed by taking every `len`-th letter.
    static func avgIC(_ nums: [Int], len: Int) -> Double {
        guard len > 0 else { return 0 }
        var total = 0.0
        for offset in 0..<len {
            var col: [Int] = []
            var i = offset
            while i < nums.count { col.append(nums[i]); i += len }
            total += ic(col)
        }
        return total / Double(len)
    }

    /// Best Caesar shift for one column by minimum chi-squared against English.
    static func bestShift(_ col: [Int]) -> Int {
        var best = 0
        var bestChi = Double.greatestFiniteMagnitude
        let n = Double(col.count)
        for shift in 0..<26 {
            var counts = [Double](repeating: 0, count: 26)
            for c in col { counts[(c - shift + 26) % 26] += 1 }
            var chi = 0.0
            for i in 0..<26 {
                let expected = english[i] * n
                if expected > 0 { chi += (counts[i] - expected) * (counts[i] - expected) / expected }
            }
            if chi < bestChi { bestChi = chi; best = shift }
        }
        return best
    }

    public struct Analysis { public let key: String; public let plaintext: String; public let keyLength: Int }

    public static func analyze(_ cipher: String, maxKeyLength: Int = 20) -> Analysis? {
        let nums = letters(cipher)
        guard nums.count >= 20 else { return nil }

        // Pick the key length whose average IC is closest to English (~0.0667),
        // preferring the shortest length that clears a strong threshold to avoid multiples.
        var scored: [(len: Int, score: Double)] = []
        for len in 1...min(maxKeyLength, nums.count / 2) {
            scored.append((len, avgIC(nums, len: len)))
        }
        let strong = scored.filter { $0.score >= 0.06 }.sorted { $0.len < $1.len }
        let chosen = strong.first?.len ?? scored.max(by: { $0.score < $1.score })?.len ?? 1

        var keyShifts: [Int] = []
        for offset in 0..<chosen {
            var col: [Int] = []
            var i = offset
            while i < nums.count { col.append(nums[i]); i += chosen }
            keyShifts.append(bestShift(col))
        }
        let key = String(keyShifts.map { Character(UnicodeScalar(UInt32($0 + 65))!) })
        return Analysis(key: key, plaintext: decrypt(cipher, key: key), keyLength: chosen)
    }

    public static func run(_ input: String) -> ToolOutput {
        // "ciphertext | KEY" decrypts with a known key; "ciphertext" alone auto-recovers it.
        var out = ToolOutput()
        if let bar = input.range(of: "|") {
            let cipher = String(input[..<bar.lowerBound]).trimmed()
            let key = String(input[bar.upperBound...]).trimmed()
            let pt = decrypt(cipher, key: key)
            var s = ReportSection("Vigenère decrypt — key \"\(key.uppercased())\"")
            s.add("Plaintext", pt, FlagHunter.find(in: pt).isEmpty ? .info : .high)
            for f in FlagHunter.find(in: pt) { out.findings.append(Finding(.high, "Possible flag: \(f)", "Vigenère key \(key)", source: "ctf")) }
            out.sections = [s]
            return out
        }
        guard let a = analyze(input.trimmed()) else {
            return ToolOutput(sections: [ReportSection("Vigenère cryptanalysis",
                items: [ReportItem("Error", "need at least ~20 letters of ciphertext to recover the key", .low)])])
        }
        var s = ReportSection("Vigenère cryptanalysis",
                              note: "Key length \(a.keyLength) found by Index of Coincidence; each letter solved by chi-squared frequency analysis.")
        s.add("Recovered key", a.key, .medium)
        s.add("Plaintext", a.plaintext, FlagHunter.find(in: a.plaintext).isEmpty ? .info : .high)
        s.note = (s.note ?? "") + "  Add \"| KEY\" to decrypt with a known key."
        for f in FlagHunter.find(in: a.plaintext) { out.findings.append(Finding(.high, "Possible flag: \(f)", "Vigenère key \(a.key)", source: "ctf")) }
        out.sections = [s]
        return out
    }
}
