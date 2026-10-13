import Foundation

// MARK: - Password & passphrase generation

public enum Generators {
    static let lower = Array("abcdefghijkmnopqrstuvwxyz")       // no l
    static let upper = Array("ABCDEFGHJKLMNPQRSTUVWXYZ")        // no I, O
    static let digits = Array("23456789")                      // no 0, 1
    static let symbols = Array("!@#$%^&*-_=+?")

    public static func password(length: Int = 20, useUpper: Bool = true, useDigits: Bool = true,
                                useSymbols: Bool = true, avoidAmbiguous: Bool = true) -> String {
        var pool = avoidAmbiguous ? lower : Array("abcdefghijklmnopqrstuvwxyz")
        if useUpper { pool += avoidAmbiguous ? upper : Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ") }
        if useDigits { pool += avoidAmbiguous ? digits : Array("0123456789") }
        if useSymbols { pool += symbols }
        let n = max(4, min(length, 128))
        var rng = SystemRandomNumberGenerator()
        return String((0..<n).map { _ in pool[Int.random(in: 0..<pool.count, using: &rng)] })
    }

    /// Memorable passphrase: N random words from the embedded list, separated and capitalised.
    public static func passphrase(words: Int = 4, separator: String = "-", capitalize: Bool = true,
                                  appendNumber: Bool = true) -> String {
        var rng = SystemRandomNumberGenerator()
        var parts: [String] = []
        for _ in 0..<max(2, min(words, 12)) {
            var w = diceware[Int.random(in: 0..<diceware.count, using: &rng)]
            if capitalize { w = w.prefix(1).uppercased() + w.dropFirst() }
            parts.append(w)
        }
        var out = parts.joined(separator: separator)
        if appendNumber { out += separator + String(Int.random(in: 10...99, using: &rng)) }
        return out
    }

    public static func run(length: Int = 20) -> ToolOutput {
        var s = ReportSection("Generated secrets", note: "Generated on-device with the system CSPRNG. Nothing is sent or stored.")
        let pw = password(length: length)
        s.add("Strong password", pw)
        s.add("  entropy", String(format: "%.0f bits", PasswordStrength.entropyBits(pw)), .info)
        s.add("Passphrase", passphrase())
        s.add("PIN (6)", String((0..<6).map { _ in Character("\(Int.random(in: 0...9))") }))
        s.add("No-symbol password", password(length: length, useSymbols: false))
        return ToolOutput(sections: [s])
    }

    // A compact word list for passphrases (subset of the EFF short list; all 4–6 letters).
    static let diceware: [String] = """
    acid acorn acre actor adept adobe agent aged agile akin alarm album alert alias alibi alien alike alive alley
    aloe aloft aloha alpha amber amble amend amigo amino ample amuse angel anger angle ankle apart apple april apron
    arena argue arise armor aroma array arrow ascot ashen aside aspen asset atlas atom attic audio audit avert avoid
    awake award aware awoke axial bacon badge bagel baker balmy banjo barge basil basin baton beach beard beast beech
    began begin being belt bench bagel berry bevel bike bingo birch bison blade blank blast blaze bleak blend bless
    blimp blink bliss block bloom blown blues bluff blunt blurt blush board boast bogus bolt bonus booth boots booze
    boss botch bound bowl brace braid brain brake brand brass brave bread break breed brick bride brief brine bring
    brink brisk broad broil broke brook broom brown brunt brush buddy budge buggy bugle build built bulge bulk bully
    bunch bunny burly burnt burst bush cabin cable cacao cache cadet cage cameo canal candy canoe canon cape card
    cargo carol carry carve catch cater cause cedar cello chalk champ chant chaos chard charm chart chase cheat check
    cheek cheer chef chess chest chew chief chili chill chime chimp chin chip chirp chive choir chomp chop chord chose
    chow chrome chuck chump chunk churn chute cider cinch civic civil claim clamp clang clank clap clash clasp class
    claw clay clean clear cleat cleft clerk click cliff climb cling clink cloak clock clone close cloth cloud clove
    clown club cluck clump clung clunk coach coast cobra cocoa code coil coin colon color colt comb comet comfy comic
    comma cone cope copy coral cord core cork corn cost couch cough could count court cover covet cozy crack craft
    cramp crane crank crash crate crave crawl crazy creak cream credo creed creek creep crepe crept crest crew crib
    """.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init)

    // MARK: - Random tokens / UUID

    public static func randomBytes(_ n: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        return (0..<max(1, n)).map { _ in UInt8.random(in: 0...255, using: &rng) }
    }

    public static func uuid() -> String { UUID().uuidString.lowercased() }

    public static func tokens(bytes: Int = 32) -> ToolOutput {
        let raw = randomBytes(bytes)
        var s = ReportSection("Random tokens (\(bytes) bytes)", note: "Cryptographically-random, generated on-device.")
        s.add("Hex", raw.map { String(format: "%02x", $0) }.joined())
        s.add("Base64", Data(raw).base64EncodedString())
        s.add("Base64URL", Data(raw).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: ""))
        s.add("UUID v4", uuid())
        s.add("Alphanumeric", password(length: bytes, useSymbols: false, avoidAmbiguous: false))
        return ToolOutput(sections: [s])
    }
}

// MARK: - Unix timestamp converter

public enum TimestampTool {
    public static func run(_ input: String) -> ToolOutput {
        let t = input.trimmed()
        var s = ReportSection("Timestamp")
        let now = Date()
        func describe(_ date: Date, label: String) {
            let iso = ISO8601DateFormatter(); iso.formatOptions = [.withInternetDateTime]
            let utc = DateFormatter(); utc.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'UTC'"; utc.timeZone = TimeZone(identifier: "UTC"); utc.locale = Locale(identifier: "en_US_POSIX")
            s.add(label, iso.string(from: date))
            s.add("  UTC", utc.string(from: date))
            s.add("  Unix (s)", String(Int(date.timeIntervalSince1970)))
            s.add("  Unix (ms)", String(Int(date.timeIntervalSince1970 * 1000)))
            let delta = date.timeIntervalSince(now)
            s.add("  Relative", relative(delta))
        }
        if t.isEmpty || t.lowercased() == "now" {
            describe(now, label: "Now")
        } else if let n = Double(t) {
            // Heuristic: 13+ digits → milliseconds, else seconds.
            let seconds = t.filter(\.isNumber).count >= 12 ? n / 1000 : n
            describe(Date(timeIntervalSince1970: seconds), label: "From epoch")
        } else {
            let iso = ISO8601DateFormatter()
            if let d = iso.date(from: t) { describe(d, label: "Parsed ISO-8601") }
            else { s.add("Error", "enter a Unix timestamp, an ISO-8601 date, or 'now'", .low) }
        }
        return ToolOutput(sections: [s])
    }

    static func relative(_ seconds: TimeInterval) -> String {
        let past = seconds < 0
        var r = abs(seconds)
        let units: [(String, Double)] = [("y", 31_536_000), ("d", 86_400), ("h", 3600), ("m", 60), ("s", 1)]
        var parts: [String] = []
        for (name, size) in units where r >= size && parts.count < 2 {
            let v = Int(r / size); r -= Double(v) * size
            parts.append("\(v)\(name)")
        }
        if parts.isEmpty { return "now" }
        return parts.joined(separator: " ") + (past ? " ago" : " from now")
    }
}

// MARK: - Hex dump

public enum HexDump {
    /// Classic xxd-style 16-byte rows with ASCII gutter.
    public static func dump(_ data: Data) -> String {
        let bytes = [UInt8](data)
        var lines: [String] = []
        var offset = 0
        while offset < bytes.count {
            let chunk = Array(bytes[offset..<min(offset + 16, bytes.count)])
            let hex = chunk.map { String(format: "%02x", $0) }
            let left = hex.prefix(8).joined(separator: " ")
            let right = hex.dropFirst(8).joined(separator: " ")
            let hexCol = (left + "  " + right).padding(toLength: 48, withPad: " ", startingAt: 0)
            let ascii = chunk.map { ($0 >= 32 && $0 < 127) ? Character(UnicodeScalar($0)) : "." }
            lines.append(String(format: "%08x  %@ |%@|", offset, hexCol, String(ascii)))
            offset += 16
        }
        return lines.joined(separator: "\n")
    }

    public static func run(_ input: String) -> ToolOutput {
        let data = Encoders.hexDecode(input) ?? Encoders.base64Decode(input) ?? Data(input.utf8)
        var s = ReportSection("Hex dump (\(data.count) bytes)",
                              note: "Interprets the input as hex or Base64 if it looks like it, otherwise raw UTF-8.")
        s.add("", dump(data.prefix(4096)))
        return ToolOutput(sections: [s])
    }
}
