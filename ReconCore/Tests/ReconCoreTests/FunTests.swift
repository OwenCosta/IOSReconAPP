import XCTest
@testable import ReconCore

final class FunTests: XCTestCase {
    // Zero-width steganography
    func testSteganographyRoundTrip() {
        let stego = Steganography.hide(secret: "flag{zw_steg}", in: "This looks totally normal.")
        XCTAssertEqual(Steganography.reveal(stego), "flag{zw_steg}")
        // the visible text is unchanged when the zero-width scalars are stripped
        var view = String.UnicodeScalarView()
        for u in stego.unicodeScalars where u != Steganography.zero && u != Steganography.one { view.append(u) }
        XCTAssertEqual(String(view), "This looks totally normal.")
        XCTAssertNil(Steganography.reveal("no hidden data here"))
    }

    // Bacon
    func testBacon() {
        XCTAssertEqual(BaconCipher.decode(BaconCipher.encode("HELLO")), "HELLO")
        // 'A' = AAAAA, 'B' = AAAAB
        XCTAssertEqual(BaconCipher.encode("AB"), "AAAAA AAAAB")
        XCTAssertEqual(BaconCipher.decode("AAAAA AAAAB"), "AB")
        XCTAssertEqual(BaconCipher.decode("00000 00001"), "AB")   // 0/1 symbols
    }

    // A1Z26
    func testA1Z26() {
        XCTAssertEqual(A1Z26.decode("8-5-12-12-15"), "hello")
        XCTAssertEqual(A1Z26.encode("hello"), "8-5-12-12-15")
        XCTAssertEqual(A1Z26.decode("6 12 1 7"), "flag")
    }

    // Alphabet decoders
    func testNATO() {
        XCTAssertEqual(AlphabetDecoders.decodeNATO("Hotel Echo Lima Lima Oscar"), "HELLO")
        XCTAssertEqual(AlphabetDecoders.decodeNATO("Foxtrot Lima Alpha Golf"), "FLAG")
    }
    func testBraille() {
        XCTAssertEqual(AlphabetDecoders.decodeBraille("\u{2813}\u{2811}\u{2807}\u{2807}\u{2815}"), "hello")
    }
    func testTapCode() {
        // H = row2,col3 ; E = row1,col5 ; L = row3,col1 ; L ; O = row3,col4
        XCTAssertEqual(AlphabetDecoders.decodeTap("2 3 1 5 3 1 3 1 3 4"), "HELLO")
        XCTAssertEqual(AlphabetDecoders.decodeTap(".. ...  . .....  ... .  ... .  ... ...."), "HELLO")
    }

    // Homoglyph
    func testHomoglyph() {
        // "pаypаl" with Cyrillic а (U+0430)
        let spoof = "p\u{0430}yp\u{0430}l.com"
        XCTAssertEqual(Homoglyph.skeleton(spoof), "paypal.com")
        let out = Homoglyph.analyze(spoof)
        XCTAssertTrue(out.findings.contains { $0.severity == .high })
        XCTAssertTrue(Homoglyph.analyze("google.com").findings.isEmpty)
    }

    // Text transforms
    func testTextFun() {
        XCTAssertEqual(TextFun.leet("elite"), "31173")   // e3 l1 i1 t7 e3
        XCTAssertEqual(TextFun.fullwidth("Hi"), "\u{FF28}\u{FF49}")
        XCTAssertEqual(String(TextFun.upsideDown("abc")), "ɔqɐ")
        XCTAssertEqual(TextFun.mockingCase("hello"), "HeLlO")
    }

    func testCatalogFunTools() {
        for id in ["steg-hide", "steg-reveal", "bacon", "a1z26", "alphabets", "homoglyph", "textfun"] {
            XCTAssertTrue(ToolCatalog.all.contains { $0.id == id }, "missing \(id)")
        }
    }
}
