import XCTest
@testable import ReconCore

final class MoreToolsTests: XCTestCase {

    // MARK: HTTP request parser

    func testParseMethodAndUrl() {
        let p = HTTPRequester.parse("POST https://api.example.com/login\nContent-Type: application/json\nX-Test: 1\n\n{\"u\":\"admin\"}")
        XCTAssertNotNil(p)
        XCTAssertEqual(p?.method, "POST")
        XCTAssertEqual(p?.url, "https://api.example.com/login")
        XCTAssertEqual(p?.headers.count, 2)
        XCTAssertEqual(p?.headers.first?.0, "Content-Type")
        XCTAssertEqual(p?.headers.first?.1, "application/json")
        XCTAssertEqual(p?.body, "{\"u\":\"admin\"}")
    }

    func testParseBareUrlDefaultsToGetAndHttps() {
        let p = HTTPRequester.parse("example.com/path")
        XCTAssertEqual(p?.method, "GET")
        XCTAssertEqual(p?.url, "https://example.com/path")
        XCTAssertEqual(p?.headers.count, 0)
        XCTAssertNil(p?.body)
    }

    func testParseCRLFAndEmptyIsNil() {
        let p = HTTPRequester.parse("GET https://x.com\r\nAccept: */*\r\n\r\n")
        XCTAssertEqual(p?.method, "GET")
        XCTAssertEqual(p?.headers.first?.0, "Accept")
        XCTAssertNil(p?.body)
        XCTAssertNil(HTTPRequester.parse("   "))
    }

    // MARK: Payload encoder

    func testPercentEncodings() {
        XCTAssertEqual(PayloadEncoder.fullPercent("<a>"), "%3C%61%3E")
        // Double-encoding preserves the hex digits: %3C -> %253C
        XCTAssertEqual(PayloadEncoder.doublePercent("<"), "%253C")
    }

    func testHtmlAndEscapeEncodings() {
        XCTAssertEqual(PayloadEncoder.htmlDecimal("<>"), "&#60;&#62;")
        XCTAssertEqual(PayloadEncoder.htmlHex("<"), "&#x3c;")
        XCTAssertEqual(PayloadEncoder.unicodeEscape("A"), "\\u0041")
        XCTAssertEqual(PayloadEncoder.hexEscape("A"), "\\x41")
    }

    func testMixedCaseAndSqlComment() {
        XCTAssertEqual(PayloadEncoder.mixedCase("script"), "ScRiPt")
        XCTAssertEqual(PayloadEncoder.sqlComment("OR 1=1"), "OR/**/1=1")
        // Non-letters are emitted unchanged without consuming the case toggle.
        XCTAssertEqual(PayloadEncoder.mixedCase("a-b-c"), "A-b-C")
    }

    func testEncoderRoundTripURL() {
        let payload = "<script>alert(1)</script>"
        let enc = PayloadEncoder.fullPercent(payload)
        XCTAssertEqual(enc.removingPercentEncoding, payload)
    }

    func testEncoderOutputHasAllRows() {
        let out = PayloadEncoder.run("' OR 1=1-- -")
        let labels = out.sections.first?.items.map(\.label) ?? []
        for expected in ["URL (full)", "URL (double)", "HTML decimal", "HTML hex", "Unicode \\u", "Hex \\x", "Base64", "Mixed case", "SQL /**/ spaces"] {
            XCTAssertTrue(labels.contains(expected), "missing \(expected)")
        }
    }

    // MARK: Wordlist builder

    func testWordsStripsTagsAndRanksByFrequency() {
        let html = """
        <html><head><style>.x{color:red}</style><script>var secret=1</script></head>
        <body><h1>Admin Portal</h1><p>Welcome admin, the admin console is ready.
        Contact support@example.com or visit portal today. 12345 2024</p></body></html>
        """
        let ranked = WordlistGen.words(from: html, minLength: 4)
        let dict = Dictionary(uniqueKeysWithValues: ranked.map { ($0.word, $0.count) })
        XCTAssertEqual(dict["admin"], 3)            // counted, case-insensitive, 3 occurrences
        XCTAssertNil(dict["color"])                 // inside <style>, stripped
        XCTAssertNil(dict["secret"])                // inside <script>, stripped
        XCTAssertNil(dict["12345"])                 // pure number, skipped
        XCTAssertNil(dict["red"])                   // too short / in style
        XCTAssertEqual(ranked.first?.word, "admin") // most frequent ranks first
        XCTAssertTrue(dict.keys.contains("portal"))
    }

    func testWordsMinLengthHonored() {
        let ranked = WordlistGen.words(from: "the quick brown fox jumps", minLength: 5)
        let words = ranked.map(\.word)
        XCTAssertTrue(words.contains("quick"))
        XCTAssertTrue(words.contains("brown"))
        XCTAssertTrue(words.contains("jumps"))
        XCTAssertFalse(words.contains("the"))
        XCTAssertFalse(words.contains("fox"))
    }
}
