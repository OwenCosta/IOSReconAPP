import Foundation

/// Monoalphabetic substitution-cipher solver: hill-climbing over key swaps, scored by an English
/// bigram model trained from an embedded corpus. Deterministic (fixed seed) so results are stable.
public enum SubstitutionSolver {

    // Small deterministic PRNG so the search is reproducible.
    struct SplitMix64 { var s: UInt64; mutating func next() -> UInt64 {
        s &+= 0x9E3779B97F4A7C15; var z = s
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31) } }

    // Trigram log-probabilities learned once from the corpus below (much stronger than bigrams).
    static let trigramLog: [Double] = {
        var counts = [Double](repeating: 0.1, count: 26 * 26 * 26)   // Laplace smoothing
        let letters = corpus.lowercased().unicodeScalars.compactMap { $0.value >= 97 && $0.value <= 122 ? Int($0.value - 97) : nil }
        for i in 0..<max(0, letters.count - 2) {
            counts[(letters[i] * 26 + letters[i + 1]) * 26 + letters[i + 2]] += 1
        }
        let total = counts.reduce(0, +)
        return counts.map { Foundation.log($0 / total) }
    }()

    static func indices(_ text: String) -> [Int] {
        text.lowercased().unicodeScalars.compactMap { $0.value >= 97 && $0.value <= 122 ? Int($0.value - 97) : nil }
    }

    /// `key[cipherLetter] = plainLetter` (both 0…25). Score the decryption of the cipher indices.
    static func score(_ cipher: [Int], key: [Int]) -> Double {
        guard cipher.count > 2 else { return -.greatestFiniteMagnitude }
        var total = 0.0
        var a = key[cipher[0]], b = key[cipher[1]]
        for i in 2..<cipher.count {
            let c = key[cipher[i]]
            total += trigramLog[(a * 26 + b) * 26 + c]
            a = b; b = c
        }
        return total
    }

    /// Returns (plaintext, key string) where key maps cipher A–Z to plaintext.
    public static func solve(_ ciphertext: String, restarts: Int = 40, seed: UInt64 = 0xC0FFEE) -> (plaintext: String, key: String) {
        let cipher = indices(ciphertext)
        guard cipher.count >= 20 else { return (ciphertext, "") }

        // Frequency-seeded starting key: most common cipher letter → most common English letter.
        let englishOrder = indices("etaoinshrdlcumwfgypbvkjxqz")
        var freq = [Int](repeating: 0, count: 26)
        for c in cipher { freq[c] += 1 }
        let cipherOrder = (0..<26).sorted { freq[$0] > freq[$1] }
        var freqKey = [Int](repeating: 0, count: 26)
        for i in 0..<26 { freqKey[cipherOrder[i]] = englishOrder[i] }

        var rng = SplitMix64(s: seed)
        var bestKey = freqKey
        var bestScore = score(cipher, key: bestKey)

        for r in 0..<restarts {
            var key = bestKey
            if r > 0 {   // shuffle a copy of the frequency key for diversity
                key = freqKey
                for i in stride(from: 25, through: 1, by: -1) {
                    let j = Int(rng.next() % UInt64(i + 1))
                    key.swapAt(i, j)
                }
            }
            var curScore = score(cipher, key: key)
            var improved = true
            while improved {
                improved = false
                for a in 0..<25 {
                    for b in (a + 1)..<26 {
                        key.swapAt(a, b)
                        let sc = score(cipher, key: key)
                        if sc > curScore { curScore = sc; improved = true }
                        else { key.swapAt(a, b) }
                    }
                }
            }
            if curScore > bestScore { bestScore = curScore; bestKey = key }
        }

        // Build plaintext preserving case and non-letters.
        var out = ""
        for ch in ciphertext.unicodeScalars {
            if ch.value >= 97 && ch.value <= 122 {
                out.unicodeScalars.append(UnicodeScalar(UInt32(97 + bestKey[Int(ch.value - 97)]))!)
            } else if ch.value >= 65 && ch.value <= 90 {
                out.unicodeScalars.append(UnicodeScalar(UInt32(65 + bestKey[Int(ch.value - 65)]))!)
            } else { out.unicodeScalars.append(ch) }
        }
        let keyStr = String((0..<26).map { Character(UnicodeScalar(UInt32(65 + bestKey[$0]))!) })
        return (out, keyStr)
    }

    public static func run(_ input: String) -> ToolOutput {
        var out = ToolOutput()
        let (plain, key) = solve(input.trimmed())
        var s = ReportSection("Substitution cipher solver",
                              note: "Hill-climbing with an English bigram model. Works best on 100+ characters; may need a re-run or manual tweaks for short texts.")
        if key.isEmpty {
            s.add("Error", "need at least ~20 letters to attempt a solve", .low)
        } else {
            s.add("Plaintext", plain, FlagHunter.find(in: plain).isEmpty ? .info : .high)
            s.add("Key (A→)", key)
            for f in FlagHunter.find(in: plain) { out.findings.append(Finding(.high, "Possible flag: \(f)", "substitution solve", source: "ctf")) }
        }
        out.sections = [s]
        return out
    }

    /// Unique lowercase words from the corpus — reused as a small English wordlist (e.g. by the hash cracker).
    public static let corpusWords: [String] = {
        var seen = Set<String>()
        return corpus.lowercased().split(whereSeparator: { !$0.isLetter }).map(String.init).filter { seen.insert($0).inserted }
    }()

    // ~1.5 KB of common English prose used only to train the bigram model.
    static let corpus = """
    The quick brown fox jumps over the lazy dog. When in the course of human events it becomes necessary for one
    people to dissolve the political bands which have connected them with another and to assume among the powers of
    the earth the separate and equal station to which the laws of nature entitle them. We hold these truths to be
    self evident that all men are created equal that they are endowed by their creator with certain unalienable
    rights that among these are life liberty and the pursuit of happiness. Four score and seven years ago our fathers
    brought forth on this continent a new nation conceived in liberty and dedicated to the proposition that all men
    are created equal. Now we are engaged in a great civil war testing whether that nation or any nation so conceived
    and so dedicated can long endure. It was the best of times it was the worst of times it was the age of wisdom it
    was the age of foolishness it was the epoch of belief it was the epoch of incredulity. To be or not to be that is
    the question whether tis nobler in the mind to suffer the slings and arrows of outrageous fortune or to take arms
    against a sea of troubles and by opposing end them. All happy families are alike each unhappy family is unhappy in
    its own way. It is a truth universally acknowledged that a single man in possession of a good fortune must be in
    want of a wife. Call me Ishmael some years ago never mind how long precisely having little or no money in my purse
    and nothing particular to interest me on shore I thought I would sail about a little and see the watery part of the
    world. The sky above the port was the color of television tuned to a dead channel.
    """
}
