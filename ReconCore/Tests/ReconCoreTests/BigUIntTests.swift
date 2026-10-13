import XCTest
@testable import ReconCore

final class BigUIntTests: XCTestCase {
    func B(_ s: String) -> BigUInt { BigUInt(decimal: s)! }

    func testParseFormatRoundTrip() {
        let s = "1234567890123456789012345678901234567890"
        XCTAssertEqual(B(s).description, s)
        XCTAssertEqual(BigUInt(hex: "ff")!.description, "255")
        XCTAssertEqual(BigUInt(hex: "0x100000000")!.description, "4294967296")
        XCTAssertEqual(B("4294967296").hexString(), "100000000")
        XCTAssertEqual(BigUInt(0).description, "0")
    }

    func testArithmetic() {
        XCTAssertEqual((B("999999999999999999") + B("1")).description, "1000000000000000000")
        XCTAssertEqual((B("1000000000000000000") - B("1")).description, "999999999999999999")
        XCTAssertEqual((B("12345678901234567890") * B("98765432109876543210")).description,
                       "1219326311370217952237463801111263526900")
    }

    func testDivMod() {
        let (q, r) = BigUInt.divMod(B("1219326311370217952237463801111263526900"), B("12345678901234567890"))
        XCTAssertEqual(q.description, "98765432109876543210")
        XCTAssertTrue(r.isZero)
        let (q2, r2) = BigUInt.divMod(B("100"), B("7"))
        XCTAssertEqual(q2.description, "14"); XCTAssertEqual(r2.description, "2")
    }

    func testModpow() {
        XCTAssertEqual(BigUInt(2).modpow(BigUInt(10), BigUInt(1000)).description, "24")
        // 4^13 mod 497 = 445 (classic example)
        XCTAssertEqual(BigUInt(4).modpow(BigUInt(13), BigUInt(497)).description, "445")
        // big: 2^256 mod (10^30)
        XCTAssertEqual(BigUInt(2).modpow(B("256"), B("1000000000000000000000000000000")).description,
                       BigUInt(hex: "10000000000000000000000000000000000000000000000000000000000000000")!.description.suffix(30).description)
    }

    func testGCDandISqrt() {
        XCTAssertEqual(BigUInt.gcd(B("1071"), B("462")).description, "21")
        XCTAssertEqual(B("1000000000000").isqrt().description, "1000000")
        XCTAssertEqual(B("1024").isqrt().description, "32")
        XCTAssertEqual(B("1023").isqrt().description, "31")
        // isqrt of a perfect square of a big prime product
        XCTAssertEqual((B("1000003") * B("1000003")).isqrt().description, "1000003")
    }

    func testBytes() {
        XCTAssertEqual(BigUInt(hex: "48656c6c6f")!.bytes(), Array("Hello".utf8))
    }
}
