import XCTest
@testable import ReconCore

final class CTFTests: XCTestCase {
    func testFlagHunter() {
        let t = "junk picoCTF{r0t_13_is_weak} more flag{a-b_c} CTF{X} nope{}"
        let f = FlagHunter.find(in: t)
        XCTAssertTrue(f.contains("picoCTF{r0t_13_is_weak}"))
        XCTAssertTrue(f.contains("flag{a-b_c}"))
        XCTAssertTrue(f.contains("CTF{X}"))
        XCTAssertTrue(FlagHunter.find(in: "nothing here").isEmpty)
    }

    func testBase32Decode() {
        // "Hi" => JBSWY===  ... use known vector "foobar" => MZXW6YTBOI======
        XCTAssertEqual(CTFEncoders.base32Decode("MZXW6YTBOI======").flatMap { String(data: $0, encoding: .utf8) }, "foobar")
        XCTAssertNil(CTFEncoders.base32Decode("!!!"))
    }

    func testBinaryAndDecimal() {
        XCTAssertEqual(CTFEncoders.fromBinary("01001000 01101001").flatMap { String(data: $0, encoding: .utf8) }, "Hi")
        XCTAssertEqual(CTFEncoders.fromDecimalBytes("72 105 33").flatMap { String(data: $0, encoding: .utf8) }, "Hi!")
        XCTAssertNil(CTFEncoders.fromBinary("0100"))          // not a byte boundary
        XCTAssertNil(CTFEncoders.fromDecimalBytes("300 1"))   // out of range
    }

    func testMagicSingleLayer() {
        // base64("flag{hello}") = ZmxhZ3toZWxsb30=
        let hits = MagicDecoder.solve("ZmxhZ3toZWxsb30=")
        XCTAssertTrue(hits.contains { $0.flags.contains("flag{hello}") })
        XCTAssertTrue(hits.first { $0.flags.contains("flag{hello}") }?.chain == ["Base64"])
    }

    func testMagicDoubleLayer() {
        // base64(base64("flag{deep}")) : inner = ZmxhZ3tkZWVwfQ==, then base64 that string
        let inner = Data("flag{deep}".utf8).base64EncodedString()
        let outer = Data(inner.utf8).base64EncodedString()
        let hits = MagicDecoder.solve(outer)
        XCTAssertTrue(hits.contains { $0.flags.contains("flag{deep}") }, "chains: \(hits.map(\.chain))")
    }

    func testMagicHexLayer() {
        let hex = Data("flag{hex}".utf8).map { String(format: "%02x", $0) }.joined()
        let hits = MagicDecoder.solve(hex)
        XCTAssertTrue(hits.contains { $0.flags.contains("flag{hex}") })
    }

    func testXORSingleByte() {
        // "flag{xor}" xor 0x42
        let plain = Array("flag{xor}".utf8)
        let xored = Data(plain.map { $0 ^ 0x42 })
        let hex = xored.map { String(format: "%02x", $0) }.joined()
        let out = XORTools.singleByteBrute(hex)
        XCTAssertTrue(out.findings.contains { $0.title.contains("flag{xor}") })
    }

    func testCaesar() {
        XCTAssertEqual(ClassicCipher.caesar("abc XYZ", shift: 3), "def ABC")
        XCTAssertEqual(ClassicCipher.caesar("def ABC", shift: -3), "abc XYZ")
        // ROT13 round trip
        XCTAssertEqual(ClassicCipher.caesar(ClassicCipher.caesar("Hello", shift: 13), shift: 13), "Hello")
        let out = ClassicCipher.run("synt{pnrfne}")   // rot13 of flag{caesar}
        XCTAssertTrue(out.findings.contains { $0.title.contains("flag{caesar}") })
    }

    func testAtbashAndRot47() {
        XCTAssertEqual(ClassicCipher.atbash("abc"), "zyx")
        XCTAssertEqual(ClassicCipher.atbash(ClassicCipher.atbash("Secret")), "Secret")
        XCTAssertEqual(ClassicCipher.rot47(ClassicCipher.rot47("Test123!")), "Test123!")
    }

    func testNumberConverter() {
        let hex = NumberConverter.run("0x41")
        let items = hex.sections.flatMap(\.items)
        XCTAssertTrue(items.contains { $0.label == "Decimal" && $0.value == "65" })
        XCTAssertTrue(items.contains { $0.label == "As character" && $0.value.contains("A") })

        let text = NumberConverter.run("Hi")
        let titems = text.sections.flatMap(\.items)
        XCTAssertTrue(titems.contains { $0.label == "Hex" && $0.value == "48 69" })
        XCTAssertTrue(titems.contains { $0.label == "Binary" && $0.value == "01001000 01101001" })
    }

    func testCatalogHasCTFCategory() {
        XCTAssertTrue(ToolCategory.allCases.contains(.ctf))
        XCTAssertEqual(ToolCategory.ctf.rawValue, "CTF")
        XCTAssertGreaterThanOrEqual(ToolCatalog.tools(in: .ctf).count, 5)
    }
}
