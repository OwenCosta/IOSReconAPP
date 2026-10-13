import Foundation

// MARK: - Bacon cipher

public enum BaconCipher {
    public static func encode(_ text: String) -> String {
        var out: [String] = []
        for ch in text.uppercased().unicodeScalars where ch.value >= 65 && ch.value <= 90 {
            let v = Int(ch.value - 65)
            out.append(String((0..<5).map { (v >> (4 - $0)) & 1 == 0 ? "A" : "B" }))
        }
        return out.joined(separator: " ")
    }

    public static func decode(_ input: String) -> String {
        // Accept A/B, a/b, or 0/1 as the two symbols; ignore everything else.
        let bits = input.compactMap { c -> Int? in
            switch c { case "A", "a", "0": return 0; case "B", "b", "1": return 1; default: return nil }
        }
        var out = ""
        var i = 0
        while i + 5 <= bits.count {
            var v = 0; for j in 0..<5 { v = (v << 1) | bits[i + j] }
            if v < 26 { out.unicodeScalars.append(UnicodeScalar(UInt32(65 + v))!) }
            i += 5
        }
        return out
    }

    public static func run(_ input: String) -> ToolOutput {
        let t = input.trimmed()
        let letters = t.filter { $0.isLetter }
        let looksEncoded = !letters.isEmpty && letters.allSatisfy { "ABab".contains($0) }
        var s = ReportSection("Bacon cipher", note: "A/B (or a/b, 0/1) in groups of five. 26-letter variant.")
        if looksEncoded || t.allSatisfy({ "01 ".contains($0) }) {
            s.add("Decoded", decode(t), .high)
        }
        s.add("Encoded", encode(t))
        var out = ToolOutput(sections: [s])
        for f in FlagHunter.find(in: decode(t)) { out.findings.append(Finding(.high, "Possible flag: \(f)", "Bacon cipher", source: "ctf")) }
        return out
    }
}

// MARK: - A1Z26 (letter ↔ number)

public enum A1Z26 {
    public static func encode(_ text: String) -> String {
        text.uppercased().unicodeScalars.compactMap { $0.value >= 65 && $0.value <= 90 ? String(Int($0.value - 64)) : nil }
            .joined(separator: "-")
    }
    public static func decode(_ input: String) -> String {
        let nums = input.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
        return String(nums.compactMap { (1...26).contains($0) ? Character(UnicodeScalar(UInt32(96 + $0))!) : nil })
    }
    public static func run(_ input: String) -> ToolOutput {
        let t = input.trimmed()
        var s = ReportSection("A1Z26", note: "A=1 … Z=26. Numbers separated by any non-digit.")
        if t.contains(where: { $0.isNumber }) { s.add("Decoded", decode(t), FlagHunter.find(in: decode(t)).isEmpty ? .info : .high) }
        if t.contains(where: { $0.isLetter }) { s.add("Encoded", encode(t)) }
        var out = ToolOutput(sections: [s])
        for f in FlagHunter.find(in: decode(t)) { out.findings.append(Finding(.high, "Possible flag: \(f)", "A1Z26", source: "ctf")) }
        return out
    }
}

// MARK: - Alphabet decoders (NATO, Braille, Tap code)

public enum AlphabetDecoders {
    static let nato: [String: Character] = [
        "alfa": "A", "alpha": "A", "bravo": "B", "charlie": "C", "delta": "D", "echo": "E", "foxtrot": "F",
        "golf": "G", "hotel": "H", "india": "I", "juliett": "J", "juliet": "J", "kilo": "K", "lima": "L",
        "mike": "M", "november": "N", "oscar": "O", "papa": "P", "quebec": "Q", "romeo": "R", "sierra": "S",
        "tango": "T", "uniform": "U", "victor": "V", "whiskey": "W", "xray": "X", "x-ray": "X", "yankee": "Y", "zulu": "Z"]

    public static func decodeNATO(_ input: String) -> String {
        input.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "," }).compactMap { nato[$0.lowercased()].map(String.init) }.joined()
    }

    static let braille: [Character: Character] = {
        let letters = "abcdefghijklmnopqrstuvwxyz"
        let patterns = "\u{2801}\u{2803}\u{2809}\u{2819}\u{2811}\u{280B}\u{281B}\u{2813}\u{280A}\u{281A}\u{2805}\u{2807}\u{280D}\u{281D}\u{2815}\u{280F}\u{281F}\u{2817}\u{280E}\u{281E}\u{2825}\u{2827}\u{283A}\u{282D}\u{283D}\u{2835}"
        var m: [Character: Character] = ["\u{2800}": " "]
        for (l, p) in zip(letters, patterns) { m[p] = l }
        return m
    }()

    public static func decodeBraille(_ input: String) -> String {
        String(input.compactMap { braille[$0] })
    }

    // Tap code 5×5 Polybius (K shares C's cell).
    static let tapGrid: [[Character]] = [["A","B","C","D","E"], ["F","G","H","I","J"], ["L","M","N","O","P"], ["Q","R","S","T","U"], ["V","W","X","Y","Z"]]

    public static func decodeTap(_ input: String) -> String {
        // Numbers (e.g. "4 4 2 3") or dot groups ("....  ..  ...  ...").
        var nums: [Int] = []
        if input.contains(".") {
            for grp in input.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "/" }) {
                let dots = grp.filter { $0 == "." }.count
                if dots > 0 { nums.append(dots) }
            }
        } else {
            nums = input.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
        }
        var out = ""
        var i = 0
        while i + 1 < nums.count {
            let r = nums[i] - 1, c = nums[i + 1] - 1
            if (0..<5).contains(r), (0..<5).contains(c) { out.append(tapGrid[r][c]) }
            i += 2
        }
        return out
    }

    public static func run(_ input: String) -> ToolOutput {
        let t = input.trimmed()
        var out = ToolOutput()
        var s = ReportSection("Alphabet decoders", note: "Auto-tries NATO phonetic, Braille and tap code.")
        var found = false
        func tryDecode(_ name: String, _ result: String) {
            guard result.count >= 2 else { return }
            s.add(name, result, FlagHunter.find(in: result).isEmpty ? .info : .high)
            found = true
            for f in FlagHunter.find(in: result) { out.findings.append(Finding(.high, "Possible flag: \(f)", name, source: "ctf")) }
        }
        tryDecode("NATO phonetic", decodeNATO(t))
        tryDecode("Braille", decodeBraille(t))
        if t.contains(where: { $0.isNumber || $0 == "." }) { tryDecode("Tap code", decodeTap(t)) }
        if !found { s.add("Result", "nothing recognised as NATO, Braille or tap code", .low) }
        out.sections = [s]
        return out
    }
}
