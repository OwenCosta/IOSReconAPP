import Foundation

/// "What is this?" — inspects a blob and tells you the likely encoding/cipher and which tool to use.
public enum Identify {
    static func matches(_ s: String, _ pattern: String) -> Bool {
        s.range(of: pattern, options: .regularExpression) != nil
    }

    public static func run(_ input: String) -> ToolOutput {
        let s = input.trimmed()
        var out = ToolOutput()
        guard !s.isEmpty else { return ToolOutput(sections: [ReportSection("Identify", items: [ReportItem("Error", "empty input", .low)])]) }

        var sig = ReportSection("Signals")
        let data = Data(s.utf8)
        sig.add("Length", "\(s.count) chars")
        sig.add("Entropy", String(format: "%.2f bits/char", SecretScanner.entropy(s)))
        let letters = Vigenere.letters(s)
        if letters.count >= 20 {
            sig.add("Index of Coincidence", String(format: "%.4f", Vigenere.ic(letters)) + "  (English ≈ 0.067, random ≈ 0.038)")
        }

        var guesses: [(String, String, Severity)] = []   // (what, suggested tool, severity)
        func add(_ what: String, _ tool: String, _ sev: Severity = .info) { guesses.append((what, tool, sev)) }

        if matches(s, #"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$"#) {
            add("JSON Web Token (JWT)", "→ JWT Secret Cracker / JWT Analyzer", .high)
        }
        if matches(s, #"^[01\s]+$"#) && s.filter({ $0 == "0" || $0 == "1" }).count % 8 == 0 {
            add("Binary (8-bit groups)", "→ Magic Decoder", .medium)
        }
        if matches(s, #"^[.\-/\s]+$"#) && s.contains(where: { $0 == "." || $0 == "-" }) {
            add("Morse code", "→ Magic Decoder", .medium)
        }
        if matches(s, #"^[0-9A-Fa-f\s]+$"#) && s.filter(\.isHexDigit).count % 2 == 0 && s.filter(\.isHexDigit).count >= 4 {
            add("Hexadecimal", "→ Magic Decoder / Hex Dump", .medium)
        }
        if matches(s, #"^[A-Z2-7]+=*$"#) && s.count % 8 == 0 {
            add("Base32", "→ Magic Decoder", .medium)
        }
        if matches(s, #"^[A-Za-z0-9+/]+=*$"#) && s.count % 4 == 0 && s.count >= 8 {
            add("Base64", "→ Magic Decoder / Smart Decoder", .medium)
        }
        if matches(s, #"^[A-Za-z0-9_-]+$"#) && (s.contains("-") || s.contains("_")) && s.count % 4 != 1 {
            add("Base64URL (URL-safe)", "→ Magic Decoder", .low)
        }
        if s.contains("%") && (s.removingPercentEncoding ?? s) != s {
            add("URL / percent-encoding", "→ Smart Decoder", .low)
        }
        if matches(s, #"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$"#) && s.count >= 6 && !matches(s, #"^[A-Za-z]+$"#) {
            add("Base58 (Bitcoin/IPFS)", "→ Magic Decoder", .low)
        }
        // Hash shapes
        let hashNames = HashIdentifier.identify(s).items.filter { $0.label == "Candidate" }.map(\.value)
        for h in hashNames.prefix(3) { add("Hash: \(h)", "→ Hash Identifier", .low) }

        // Classical cipher heuristics on letter-only text.
        if letters.count >= 20, guesses.isEmpty || guesses.allSatisfy({ $0.2 == .low }) {
            let ic = Vigenere.ic(letters)
            if ic >= 0.06 {
                add("English plaintext, or a monoalphabetic shift (Caesar/Atbash)", "→ Caesar / ROT Breaker", .medium)
            } else if ic < 0.05 {
                add("Polyalphabetic cipher (Vigenère-like)", "→ Vigenère Breaker", .medium)
            }
        }

        if !FlagHunter.find(in: s).isEmpty {
            add("Already contains a flag pattern", "→ done, copy it", .high)
        }
        if guesses.isEmpty {
            let e = SecretScanner.entropy(s)
            if e > 4.5 { add("High-entropy: likely encrypted, compressed, or random", "→ XOR Brute-force, or inspect as Hex Dump", .low) }
            else { add("No strong signal: may be plaintext or an unknown scheme", "→ try Magic Decoder", .low) }
        }

        var res = ReportSection("Likely identity", note: "Best-guess classification and the tool to reach for.")
        for g in guesses {
            res.add(g.0, g.1, g.2)
            if g.2 >= .medium { out.findings.append(Finding(g.2, g.0, g.1, source: "identify")) }
        }
        out.sections = [res, sig]
        return out
    }
}
