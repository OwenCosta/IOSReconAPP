import Foundation

/// Detects homoglyph / lookalike characters — the trick behind IDN homograph phishing domains
/// (e.g. "аpple.com" with a Cyrillic а). Maps confusables to an ASCII skeleton and flags mixed scripts.
public enum Homoglyph {
    // A pragmatic confusables table (Cyrillic/Greek/fullwidth/misc → ASCII).
    static let confusables: [Character: Character] = [
        // Cyrillic
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ԁ": "d",
        "ј": "j", "һ": "h", "ԛ": "q", "ԝ": "w", "ɡ": "g", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
        "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y",
        // Greek
        "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "Ο": "O", "Α": "A", "Ρ": "P", "Β": "B",
        "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Τ": "T", "Υ": "Y", "Χ": "X",
        // misc lookalikes
        "ɩ": "l", "ǀ": "l", "І": "I", "１": "1", "０": "0", "ｏ": "o", "ⅼ": "l", "ℓ": "l", "𝐚": "a"
    ]

    public static func skeleton(_ s: String) -> String {
        String(s.map { confusables[$0] ?? $0 })
    }

    static func script(of scalar: Unicode.Scalar) -> String? {
        switch scalar.value {
        case 0x41...0x5A, 0x61...0x7A: return "Latin"
        case 0x0400...0x04FF: return "Cyrillic"
        case 0x0370...0x03FF: return "Greek"
        case 0x0530...0x058F: return "Armenian"
        case 0x4E00...0x9FFF: return "CJK"
        default: return nil
        }
    }

    public static func analyze(_ input: String) -> ToolOutput {
        let s = input.trimmed()
        var out = ToolOutput()
        var sec = ReportSection("Homoglyph analysis", note: "Flags non-ASCII lookalikes and mixed scripts, the IDN homograph phishing trick.")

        var suspicious: [(Character, String)] = []
        var scripts = Set<String>()
        for ch in s {
            for u in ch.unicodeScalars { if let sc = script(of: u) { scripts.insert(sc) } }
            if let ascii = confusables[ch] { suspicious.append((ch, String(ascii))) }
            else if ch.unicodeScalars.contains(where: { $0.value > 0x7F }) && ch.isLetter {
                suspicious.append((ch, "?"))
            }
        }
        let skel = skeleton(s)
        sec.add("Input", s)
        sec.add("ASCII skeleton", skel, skel != s ? .high : .info)
        sec.add("Scripts present", scripts.sorted().joined(separator: ", "), scripts.count > 1 ? .high : .info)

        if scripts.count > 1 {
            sec.add("Verdict", "MIXED SCRIPTS: classic homograph spoofing", .high)
            out.findings.append(Finding(.high, "Mixed-script string (possible homograph attack)", "Scripts: \(scripts.sorted().joined(separator: ", ")) · looks like \"\(skel)\"", source: "homoglyph"))
        } else if !suspicious.isEmpty {
            sec.add("Verdict", "Non-ASCII lookalikes present", .medium)
            out.findings.append(Finding(.medium, "Lookalike characters present", "Resembles \"\(skel)\"", source: "homoglyph"))
        } else {
            sec.add("Verdict", "all ASCII, no homoglyphs", .info)
        }

        if !suspicious.isEmpty {
            var det = ReportSection("Suspicious characters (\(suspicious.count))")
            for (ch, ascii) in suspicious.prefix(40) {
                let u = ch.unicodeScalars.first.map { String(format: "U+%04X", $0.value) } ?? "?"
                det.add("‘\(ch)’  \(u)", "looks like ‘\(ascii)’", .medium)
            }
            out.sections = [sec, det]
        } else {
            out.sections = [sec]
        }
        return out
    }
}
