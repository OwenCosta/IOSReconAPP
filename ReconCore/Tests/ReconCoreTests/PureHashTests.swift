import XCTest
@testable import ReconCore

final class PureHashTests: XCTestCase {
    func b(_ s: String) -> [UInt8] { Array(s.utf8) }
    func testMD5() {
        XCTAssertEqual(PureHash.hex(PureHash.md5(b(""))), "d41d8cd98f00b204e9800998ecf8427e")
        XCTAssertEqual(PureHash.hex(PureHash.md5(b("abc"))), "900150983cd24fb0d6963f7d28e17f72")
        XCTAssertEqual(PureHash.hex(PureHash.md5(b("The quick brown fox jumps over the lazy dog"))), "9e107d9d372bb6826bd81d3542a419d6")
    }
    func testSHA1() {
        XCTAssertEqual(PureHash.hex(PureHash.sha1(b("abc"))), "a9993e364706816aba3e25717850c26c9cd0d89d")
        XCTAssertEqual(PureHash.hex(PureHash.sha1(b(""))), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    }
    func testSHA256() {
        XCTAssertEqual(PureHash.hex(PureHash.sha256(b("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(PureHash.hex(PureHash.sha256(b(""))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(PureHash.hex(PureHash.sha256(b("The quick brown fox jumps over the lazy dog"))), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
    }
    func testHMAC() {
        let key = [UInt8](repeating: 0x0b, count: 20)
        XCTAssertEqual(PureHash.hex(PureHash.hmac(key: key, message: b("Hi There"), hash: PureHash.sha256)),
                       "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    }
}
