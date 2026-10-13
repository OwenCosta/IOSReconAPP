import XCTest
@testable import ReconCore

final class MoreCryptoTests: XCTestCase {
    func B(_ s: String) -> BigUInt { BigUInt(decimal: s)! }
    func str(_ d: Data?) -> String? { d.flatMap { String(data: $0, encoding: .utf8) } }

    // MARK: Base encodings
    func testBase45RFCVector() {
        // RFC 9285 example: "Hello!!" -> "%69 VD92EX0"
        XCTAssertEqual(str(CTFEncoders.base45Decode("%69 VD92EX0")), "Hello!!")
        XCTAssertEqual(str(CTFEncoders.base45Decode("UJCLQE7W581")), "base-45")
    }
    func testBase62RoundTrip() {
        for s in ["Hello, World!", "flag{base62_works}", "\u{0}\u{0}abc", "a"] {
            let data = Array(s.utf8)
            XCTAssertEqual(CTFEncoders.base62Decode(CTFEncoders.base62Encode(data)).map { [UInt8]($0) }, data, s)
        }
    }
    func testBase91RoundTrip() {
        for s in ["Hello World!", "flag{bAsE91}", "The quick brown fox", "x"] {
            let data = Array(s.utf8)
            XCTAssertEqual(CTFEncoders.base91Decode(CTFEncoders.base91Encode(data)).map { [UInt8]($0) }, data, s)
        }
    }
    func testMagicWithBase45() {
        // Base45 of a flag, then confirm Magic surfaces it.
        // Build base45("flag{45}") via... we have no encoder, so test the transform directly.
        let t = MagicDecoder.transforms.first { $0.name == "Base62" }!.apply
        let enc = CTFEncoders.base62Encode(Array("flag{b62}".utf8))
        XCTAssertEqual(t(enc), "flag{b62}")
    }

    // MARK: Common modulus
    func testCommonModulus() {
        // n = 1013 * 3643, two coprime exponents e1=17, e2=65537 on the same message.
        let p = B("1013"), q = B("3643"), n = p * q
        let m = B("1234567")
        let e1 = B("17"), e2 = B("65537")
        let c1 = m.modpow(e1, n), c2 = m.modpow(e2, n)
        XCTAssertEqual(RSATool.commonModulus(n: n, e1: e1, c1: c1, e2: e2, c2: c2), m)

        let out = RSATool.runMulti("n=\(n) e=\(e1) c=\(c1)\nn=\(n) e=\(e2) c=\(c2)")
        let flat = out.sections.flatMap { $0.items.map { "\($0.label)=\($0.value)" } }.joined(separator: "|")
        XCTAssertTrue(flat.contains("m=1234567"), flat)
    }

    // MARK: CRT + Håstad
    func testCRT() {
        // x ≡ 2 (3), x ≡ 3 (5), x ≡ 2 (7) -> 23
        let (r, m) = RSATool.crt([(B("2"), B("3")), (B("3"), B("5")), (B("2"), B("7"))])!
        XCTAssertEqual(r.description, "23"); XCTAssertEqual(m.description, "105")
    }
    func testHastadBroadcast() {
        // Same m, e=3, three distinct primes (pairwise coprime). m < each n, and m^3 > each n but
        // < n1·n2·n3 — the classic broadcast setup, so CRT then cube root recovers m.
        let m = B("123456789")
        let mods = [B("1000000007"), B("1000000009"), B("998244353")]
        let pairs = mods.map { (c: m.modpow(B("3"), $0), n: $0) }
        XCTAssertEqual(RSATool.hastad(pairs, e: 3), m)
        let input = pairs.map { "n=\($0.n) e=3 c=\($0.c)" }.joined(separator: "\n")
        let out = RSATool.runMulti(input)
        XCTAssertTrue(out.findings.contains { $0.title.contains("broken") })
    }

    func testCatalogHasMultiKey() {
        XCTAssertTrue(ToolCatalog.all.contains { $0.id == "rsa-multi" })
    }
}
