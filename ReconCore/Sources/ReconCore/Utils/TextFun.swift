import Foundation

/// Playful text transforms — leetspeak, reversal, upside-down, full-width and mocking case.
/// Handy for CTF flavour text, usernames and the occasional obfuscation challenge.
public enum TextFun {
    static let leetMap: [Character: Character] = ["a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "b": "8", "g": "9", "l": "1"]
    public static func leet(_ s: String) -> String {
        String(s.map { leetMap[Character($0.lowercased())] ?? $0 })
    }

    static let flipMap: [Character: Character] = [
        "a": "ɐ", "b": "q", "c": "ɔ", "d": "p", "e": "ǝ", "f": "ɟ", "g": "ƃ", "h": "ɥ", "i": "ᴉ", "j": "ɾ",
        "k": "ʞ", "l": "l", "m": "ɯ", "n": "u", "o": "o", "p": "d", "q": "b", "r": "ɹ", "s": "s", "t": "ʇ",
        "u": "n", "v": "ʌ", "w": "ʍ", "x": "x", "y": "ʎ", "z": "z", "?": "¿", "!": "¡", ".": "˙", ",": "'", "'": ",",
        "(": ")", ")": "(", "[": "]", "]": "[", "<": ">", ">": "<", "_": "‾"]
    public static func upsideDown(_ s: String) -> String {
        String(s.lowercased().reversed().map { flipMap[$0] ?? $0 })
    }

    public static func fullwidth(_ s: String) -> String {
        String(s.unicodeScalars.map { u -> Character in
            if u.value == 0x20 { return "\u{3000}" }
            if u.value >= 0x21 && u.value <= 0x7E { return Character(UnicodeScalar(u.value + 0xFEE0)!) }
            return Character(u)
        })
    }

    public static func mockingCase(_ s: String) -> String {
        var upper = false
        return String(s.map { ch -> Character in
            guard ch.isLetter else { return ch }
            upper.toggle()
            return upper ? Character(ch.uppercased()) : Character(ch.lowercased())
        })
    }

    public static func run(_ input: String) -> ToolOutput {
        let s = input.isEmpty ? "Hack the planet" : input
        var sec = ReportSection("Text transforms")
        sec.add("Leetspeak", leet(s))
        sec.add("Reversed", String(s.reversed()))
        sec.add("Upside-down", upsideDown(s))
        sec.add("Full-width", fullwidth(s))
        sec.add("MoCkInG cAsE", mockingCase(s))
        sec.add("UPPER / lower", "\(s.uppercased())  /  \(s.lowercased())")
        return ToolOutput(sections: [sec])
    }
}
