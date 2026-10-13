import Foundation

/// Zero-width steganography: hide a secret message inside ordinary-looking text using invisible
/// zero-width characters. A real CTF/exfil technique — the carrier text looks completely normal.
public enum Steganography {
    // Zero-width scalars. We work at the scalar level because these combine into grapheme
    // clusters with neighbouring characters, so iterating a String by Character would drop them.
    static let zero: Unicode.Scalar = "\u{200B}"   // zero-width space       → bit 0
    static let one: Unicode.Scalar = "\u{200C}"    // zero-width non-joiner  → bit 1

    public static func hide(secret: String, in cover: String) -> String {
        let bits = [UInt8](secret.utf8).flatMap { byte in (0..<8).map { (byte >> (7 - $0)) & 1 } }
        var payload = String.UnicodeScalarView()
        for bit in bits { payload.append(bit == 0 ? zero : one) }
        // Append the payload at the end; the visible cover text is left intact.
        return cover + String(payload)
    }

    public static func reveal(_ text: String) -> String? {
        let bits: [Int] = text.unicodeScalars.compactMap { $0 == zero ? 0 : ($0 == one ? 1 : nil) }
        guard bits.count >= 8 else { return nil }
        var bytes: [UInt8] = []
        var i = 0
        while i + 8 <= bits.count {
            var b = 0; for j in 0..<8 { b = (b << 1) | bits[i + j] }
            bytes.append(UInt8(b)); i += 8
        }
        return String(bytes: bytes, encoding: .utf8)
    }

    public static func runHide(_ input: String) -> ToolOutput {
        let parts = input.components(separatedBy: "::")
        let secret = parts[0].trimmed()
        let cover = parts.count > 1 ? parts[1].trimmed() : "This is a perfectly normal sentence."
        guard !secret.isEmpty else {
            return ToolOutput(sections: [ReportSection("Hide text", items: [ReportItem("Usage", "secret message ::cover text", .low)])])
        }
        let stego = hide(secret: secret, in: cover)
        var s = ReportSection("Hidden message", note: "Copy the line below — the secret is encoded in invisible zero-width characters.")
        s.add("Carrier (copy this)", stego)
        s.add("Length", "\(stego.count) chars (\(cover.count) visible)")
        s.add("Reveal with", "the Reveal Hidden Text tool")
        return ToolOutput(sections: [s])
    }

    public static func runReveal(_ input: String) -> ToolOutput {
        var out = ToolOutput()
        var s = ReportSection("Hidden message")
        if let secret = reveal(input), !secret.isEmpty {
            s.add("Revealed", secret, .high)
            for f in FlagHunter.find(in: secret) { out.findings.append(Finding(.high, "Possible flag: \(f)", "zero-width steganography", source: "ctf")) }
            let count = input.unicodeScalars.filter { $0 == zero || $0 == one }.count
            s.add("Zero-width chars", "\(count)")
        } else {
            s.add("Result", "no zero-width message found", .low)
        }
        out.sections = [s]
        return out
    }
}
