import XCTest
@testable import ReconCore

final class AttackTests: XCTestCase {
    func B(_ s: String) -> BigUInt { BigUInt(decimal: s)! }

    // MARK: Wiener's attack
    func testWiener() {
        // Classic small-d example: n, e with d=7 (Boneh/Durfee style small exponent).
        // Build it: p=... use known textbook vector.
        // p=1009, q=3643 -> n=3675787, phi=3671136; pick small d=7 (gcd(7,phi)=1), e=d^{-1} mod phi.
        let p = B("1013"), q = B("3643")
        let n = p * q
        let phi = (p - BigUInt(1)) * (q - BigUInt(1))
        let d = B("7")
        let e = RSATool.modInverse(d, phi)!     // large e
        XCTAssertEqual(RSATool.wiener(e: e, n: n), d)
    }
    func testWienerViaRunDecrypts() {
        let p = B("1013"), q = B("3643"), n = p * q
        let phi = (p - BigUInt(1)) * (q - BigUInt(1))
        let d = B("7")
        let e = RSATool.modInverse(d, phi)!
        let m = B("1234567")
        let c = m.modpow(e, n)
        let out = RSATool.run("n=\(n)\ne=\(e)\nc=\(c)")
        let flat = out.sections.flatMap { $0.items.map { "\($0.label)=\($0.value)" } }.joined(separator: "|")
        XCTAssertTrue(flat.contains("d (private exponent)=7"), flat)
        XCTAssertTrue(flat.contains("Decrypted m=1234567"), flat)
    }

    // MARK: Repeating-key XOR
    func testRepeatingKeyBreak() {
        let plain = Array("""
        the index of coincidence is useful in breaking polyalphabetic ciphers because natural language has a
        characteristic letter distribution that repeats across the columns defined by the key length and this
        structure survives the exclusive or operation when a short key is reused again and again over the message
        """.utf8)
        let key = Array("ICE".utf8)
        let cipher = plain.enumerated().map { $0.element ^ key[$0.offset % key.count] }
        let (k, pt) = XORAnalysis.breakRepeatingKey(cipher)!
        XCTAssertEqual(k, key)
        XCTAssertEqual(pt, plain)
    }
    func testHamming() {
        XCTAssertEqual(XORAnalysis.hamming(Array("this is a test".utf8), Array("wokka wokka!!!".utf8)), 37)
    }

    // MARK: Crib drag
    func testCribDrag() {
        let key = Array("SUPERSECRETKEY!!".utf8)
        let m1 = Array("the password is ".utf8)
        let m2 = Array("meet me at seven".utf8)
        let c1 = m1.enumerated().map { $0.element ^ key[$0.offset % key.count] }
        let c2 = m2.enumerated().map { $0.element ^ key[$0.offset % key.count] }
        let hits = XORAnalysis.cribDrag(c1, c2, crib: "the password is ")
        XCTAssertTrue(hits.contains { $0.offset == 0 && $0.text == "meet me at seven" }, "\(hits)")
    }

    // MARK: Hash cracker
    func testHashCracker() {
        let md5pw = Digests.hex(.md5, "password")!
        XCTAssertEqual(HashCracker.crack(md5pw, kind: .md5, maxPIN: 0), "password")
        let sha1 = Digests.hex(.sha1, "1337")!
        XCTAssertEqual(HashCracker.crack(sha1, kind: .sha1, maxPIN: 2000), "1337")
        let sha256 = Digests.hex(.sha256, "letmein")!
        XCTAssertEqual(HashCracker.crack(sha256, kind: .sha256, maxPIN: 0), "letmein")
        XCTAssertNil(HashCracker.crack(String(repeating: "a", count: 32), kind: .md5, maxPIN: 10))
    }

    func testCatalogGrewAgain() {
        XCTAssertTrue(ToolCatalog.all.contains { $0.id == "xor-repeating" })
        XCTAssertTrue(ToolCatalog.all.contains { $0.id == "hash-crack" })
        XCTAssertGreaterThanOrEqual(ToolCatalog.tools(in: .ctf).count, 12)
    }
}
