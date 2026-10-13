import XCTest
@testable import ReconCore

final class FeaturesTests: XCTestCase {

    // MARK: Subdomain source parsers
    func testCrtshParser() {
        let json = Data(#"[{"name_value":"a.example.com\n*.b.example.com","common_name":"c.example.com"},{"name_value":"other.org"}]"#.utf8)
        let got = SubdomainSources.parseCrtsh(json, domain: "example.com")
        XCTAssertEqual(got, ["a.example.com", "b.example.com", "c.example.com"])
    }
    func testCertspotterParser() {
        let json = Data(#"[{"dns_names":["x.example.com","*.y.example.com","evil.org"]}]"#.utf8)
        XCTAssertEqual(SubdomainSources.parseCertspotter(json, domain: "example.com"), ["x.example.com", "y.example.com"])
    }
    func testJSONArrayAndOTXParsers() {
        XCTAssertEqual(SubdomainSources.parseJSONArray(Data(#"["m.example.com","n.example.com","x.org"]"#.utf8), domain: "example.com"),
                       ["m.example.com", "n.example.com"])
        XCTAssertEqual(SubdomainSources.parseOTX(Data(#"{"passive_dns":[{"hostname":"p.example.com"},{"hostname":"q.other.com"}]}"#.utf8), domain: "example.com"),
                       ["p.example.com"])
    }
    func testHostLinesAndScrape() {
        XCTAssertEqual(SubdomainSources.parseHostLines("a.example.com,1.2.3.4\nb.example.com,5.6.7.8\n", domain: "example.com"),
                       ["a.example.com", "b.example.com"])
        let html = "<td>foo.example.com</td> junk bar.example.com, notexample.com x.EXAMPLE.com"
        let got = SubdomainSources.scrapeHostnames(html, domain: "example.com")
        XCTAssertTrue(got.isSuperset(of: ["foo.example.com", "bar.example.com", "x.example.com"]))
        XCTAssertFalse(got.contains("notexample.com"))
    }
    func testCleanFiltersForeignAndApex() {
        XCTAssertEqual(SubdomainSources.clean("*.Sub.Example.com.", domain: "example.com"), "sub.example.com")
        XCTAssertEqual(SubdomainSources.clean("example.com", domain: "example.com"), "example.com")
        XCTAssertNil(SubdomainSources.clean("evil.com", domain: "example.com"))
        XCTAssertNil(SubdomainSources.clean("notexample.com", domain: "example.com"))
    }

    // MARK: Generators
    func testPasswordRespectsOptions() {
        let p = Generators.password(length: 200)
        XCTAssertEqual(p.count, 128)   // capped at 128
        XCTAssertFalse(p.contains(where: { "0O1lI".contains($0) }), "ambiguous chars present: \(p)")
        let noSym = Generators.password(length: 60, useSymbols: false)
        XCTAssertFalse(noSym.contains(where: { "!@#$%^&*-_=+?".contains($0) }))
        XCTAssertEqual(Generators.password(length: 1).count, 4)   // floored at 4
    }
    func testPassphraseShape() {
        let p = Generators.passphrase(words: 4, separator: "-", capitalize: true, appendNumber: true)
        let parts = p.split(separator: "-")
        XCTAssertEqual(parts.count, 5)                       // 4 words + number
        XCTAssertNotNil(Int(parts.last!))
        XCTAssertTrue(parts.first!.first!.isUppercase)
    }
    func testRandomBytesAndUUID() {
        XCTAssertEqual(Generators.randomBytes(16).count, 16)
        XCTAssertNotEqual(Generators.randomBytes(16), Generators.randomBytes(16))
        XCTAssertTrue(Generators.uuid().range(of: #"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"#, options: .regularExpression) != nil)
    }

    // MARK: Timestamp & hex dump
    func testTimestamp() {
        let items = TimestampTool.run("1700000000").sections.flatMap(\.items)
        XCTAssertTrue(items.contains { $0.label == "  Unix (s)" && $0.value == "1700000000" })
        // milliseconds collapse to the same instant
        let ms = TimestampTool.run("1700000000000").sections.flatMap(\.items)
        XCTAssertTrue(ms.contains { $0.label == "  Unix (s)" && $0.value == "1700000000" })
    }
    func testHexDump() {
        let d = HexDump.dump(Data("Hello".utf8))
        XCTAssertTrue(d.contains("48 65 6c 6c 6f"))
        XCTAssertTrue(d.contains("|Hello|"))
        XCTAssertTrue(d.hasPrefix("00000000"))
    }

    // MARK: Identify
    func testIdentify() {
        func labels(_ s: String) -> [String] { Identify.run(s).sections.first!.items.map(\.label) }
        XCTAssertTrue(labels("SGVsbG8gV29ybGQh").contains { $0.contains("Base64") })
        XCTAssertTrue(labels("48656c6c6f").contains { $0.contains("Hex") })
        XCTAssertTrue(labels(".... . .-.. .-.. ---").contains { $0.contains("Morse") })
        XCTAssertTrue(labels("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc").contains { $0.contains("JWT") })
        XCTAssertTrue(labels("01001000 01101001").contains { $0.contains("Binary") })
    }

    func testCatalogCategories() {
        XCTAssertTrue(ToolCategory.allCases.contains(.generators))
        XCTAssertGreaterThanOrEqual(ToolCatalog.tools(in: .generators).count, 2)
        XCTAssertTrue(ToolCatalog.all.contains { $0.id == "subdomains" })
        XCTAssertTrue(ToolCatalog.all.contains { $0.id == "identify" })
    }
}
