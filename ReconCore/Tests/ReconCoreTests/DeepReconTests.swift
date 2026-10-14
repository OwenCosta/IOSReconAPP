import XCTest
@testable import ReconCore

final class DeepReconTests: XCTestCase {
    // MurmurHash3 x86_32 known vectors (match python mmh3.hash)
    func testMurmur3() {
        XCTAssertEqual(MurmurHash3.hash32(Array("".utf8)), 0)
        XCTAssertEqual(MurmurHash3.hash32(Array("foo".utf8)), -156908512)
        XCTAssertEqual(MurmurHash3.hash32(Array("hello".utf8)), 613153351)
    }
    func testFaviconHashStable() {
        let data = Data((0..<64).map { UInt8($0) })
        XCTAssertEqual(FaviconHash.hash(data), FaviconHash.hash(data))   // deterministic
    }

    // Endpoint extraction
    func testEndpointExtract() {
        let js = """
        fetch("/api/v1/users?id=1"); var u='https://cdn.example.com/app.js';
        axios.get('/admin/login'); const img="/images/logo.png"; load("config.json");
        """
        let eps = EndpointExtractor.extract(from: js)
        XCTAssertTrue(eps.contains("/api/v1/users?id=1"))
        XCTAssertTrue(eps.contains("https://cdn.example.com/app.js"))
        XCTAssertTrue(eps.contains("config.json"))
        let (_, _, interesting) = EndpointExtractor.classify(eps)
        XCTAssertTrue(interesting.contains("/api/v1/users?id=1"))
        XCTAssertTrue(interesting.contains("/admin/login"))
    }

    // Dorks
    func testDorks() {
        let dorks = Dorks.forDomain("example.com").map(\.1)
        XCTAssertTrue(dorks.contains("site:example.com"))
        XCTAssertTrue(dorks.contains { $0.contains("intitle:\"index of\"") })
        XCTAssertNil(TargetParser.domain(from: "8.8.8.8"))   // dorks require a domain
    }

    // Username permutations
    func testUsernames() {
        let p = UsernameGen.permutations(first: "John", last: "Doe")
        XCTAssertTrue(p.contains("jdoe"))
        XCTAssertTrue(p.contains("john.doe"))
        XCTAssertTrue(p.contains("j.doe"))
        XCTAssertEqual(Set(p).count, p.count)   // deduped
        let out = UsernameGen.run("John Doe :: corp.com")
        XCTAssertTrue(out.sections.first!.items.contains { $0.value == "jdoe@corp.com" })
    }

    // Nmap / payloads / crack builders produce output
    func testBuilders() {
        XCTAssertTrue(NmapBuilder.run("10.0.0.1").sections.first!.items.contains { $0.value.contains("nmap -sV") })
        XCTAssertFalse(PayloadLibrary.run("xss").sections.isEmpty)
        XCTAssertTrue(PayloadLibrary.run("ssti").sections.first!.items.contains { $0.value.contains("{{7*7}}") })
        XCTAssertTrue(CrackCommands.run("5f4dcc3b5aa765d61d8327deb882cf99").sections.first!.items.contains { $0.value.contains("hashcat -m") })
    }

    func testCatalogDeepTools() {
        for id in ["favicon", "endpoints", "dorks", "payloads", "nmap", "crack-cmd", "usernames"] {
            XCTAssertTrue(ToolCatalog.all.contains { $0.id == id }, "missing \(id)")
        }
    }
}
