import XCTest
@testable import ReconCore

final class X509Tests: XCTestCase {
    // Generated with: openssl req -x509 -newkey rsa:2048 ... -addext subjectAltName=DNS:test.example.com,DNS:*.wild.example.com,IP:10.1.2.3
    static let rsaDER = Data(base64Encoded: "MIIDkDCCAnigAwIBAgIUfQeQdVmqpHYOCcU5IRBffQnTawgwDQYJKoZIhvcNAQELBQAwOzELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMB4XDTI2MTAxMzE2MDIyOFoXDTI3MDExMTE2MDIyOFowOzELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqMJ0oSq98HMbsVIOQzs+wZaHUXEKRb+mCkjizjV4y2zISu7xDnd6pQZ7wB67GZpLAlH4xhdycwIBy4rDnlzUi2+oqvOUgFl43otwVJwcTjIQwKSU7ZivhUIXQfl96W+oKpJDZZmZKTSlKZSywiM0G3x/BIB31qi0tafGKH9u3xMYwkBUzEIznkIIU1T56Z7VdArGEvfh/UBfiCovJ/Ch4Ysc/fi6Njxg5wkDMQkbb+pqxHB5GZFEUQOk0b6jgOwQlvp7PbzZLwbJiFrpyASIOxS9Bk1wsct9/5eliC/OePKR90UAz6DMf6oHbl6Qv/xurzKfSDpJDB3DcLsENu18eQIDAQABo4GLMIGIMB0GA1UdDgQWBBS4wjTQZnIfM/kMWKjUjB5RVEdOuzAfBgNVHSMEGDAWgBS4wjTQZnIfM/kMWKjUjB5RVEdOuzA1BgNVHREELjAsghB0ZXN0LmV4YW1wbGUuY29tghIqLndpbGQuZXhhbXBsZS5jb22HBAoBAgMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAYcSOiA0vKmjL77lusB0N1deA8KSnh4XcFvmhmKvCO5hNCKnqFqgqUbXwcjOwAxz8wgtfbZYWL7kctRXOAI1wgRAhqB1XVxM7CprvgRsEhmCXLB1K4F5Ae5GO6TbUV6g+KDSzlonCnMkXQN8TeBYmAvMf1l/ACT3kNm/vE12vkJHncPtGeHnjBzXsLoXombCpySfXgMiE8oBb2YxU+LdHhlNjE1keVpwGN1wIsjqX+u+MikRfjpMrDBLDB5yqk2SnvFNtP0seFUzUGurRQHWZ1EE5h58+tvDDVy6VNpTRAaqwFiRtgUvfrkEgME6OG8XdOp8YOpTnE0MLkkXub1RDdQ==")!
    // openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 ... CN=ec.example.org
    static let ecDER = Data(base64Encoded: "MIIBojCCAUigAwIBAgIUfxRc3rKTtedT9qoaPe6+Dxy2QD8wCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOZWMuZXhhbXBsZS5vcmcwHhcNMjYxMDEzMTYwMjI4WhcNMjYxMTEyMTYwMjI4WjAZMRcwFQYDVQQDDA5lYy5leGFtcGxlLm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBxudTQ74geDd7H3VkFF082wrNA5H8NoEK5mWr6g6Cde1+YjrFfMdzf9qDtLgukOG4Ztm2XEyeqpEhqfnxjhHZajbjBsMB0GA1UdDgQWBBTNDVv8fMnLEwc3mUIGolslR0DLATAfBgNVHSMEGDAWgBTNDVv8fMnLEwc3mUIGolslR0DLATAPBgNVHRMBAf8EBTADAQH/MBkGA1UdEQQSMBCCDmVjLmV4YW1wbGUub3JnMAoGCCqGSM49BAMCA0gAMEUCIGQPiJtsfdtiZNZypT4TMmIAHKg/6Sw2Y5eHfdGAVZOyAiEApog/pMeiCsuAcXqJGZwtJmMuqSOqhu4JK8tVH1cVeH0=")!

    func testRSACertificate() throws {
        let c = try XCTUnwrap(X509.parse(der: Self.rsaDER))
        XCTAssertEqual(c.subjectCN, "test.example.com")
        XCTAssertEqual(c.issuerCN, "test.example.com")
        XCTAssertEqual(c.subject, "C=US, O=Test Org, CN=test.example.com")
        XCTAssertTrue(c.selfSigned)
        XCTAssertTrue(c.isCA)
        XCTAssertEqual(c.version, 3)
        XCTAssertEqual(c.keyAlgorithm, "RSA")
        XCTAssertEqual(c.keyBits, 2048)
        XCTAssertEqual(c.signatureAlgorithm, "sha256WithRSA")
        XCTAssertEqual(c.subjectAltNames, ["test.example.com", "*.wild.example.com", "10.1.2.3"])
        XCTAssertEqual(c.serialHex, "7D:07:90:75:59:AA:A4:76:0E:09:C5:39:21:10:5F:7D:09:D3:6B:08")
        XCTAssertEqual(c.validityDays, 90)
        var cal = Calendar(identifier: .gregorian); cal.timeZone = TimeZone(identifier: "UTC")!
        let nb = cal.dateComponents([.year, .month, .day, .hour, .minute, .second], from: c.notBefore)
        XCTAssertEqual([nb.year, nb.month, nb.day, nb.hour, nb.minute, nb.second], [2026, 10, 13, 16, 2, 28])
        let na = cal.dateComponents([.year, .month, .day], from: c.notAfter)
        XCTAssertEqual([na.year, na.month, na.day], [2027, 1, 11])
        #if canImport(CryptoKit)
        XCTAssertEqual(c.sha256.uppercased(), "4EB0FC375DF4939D5343A35312A0A0E380231FD6152F29F970 04A95BD71086F4".replacingOccurrences(of: " ", with: ""))
        #endif
    }

    func testECCertificate() throws {
        let c = try XCTUnwrap(X509.parse(der: Self.ecDER))
        XCTAssertEqual(c.subjectCN, "ec.example.org")
        XCTAssertEqual(c.keyAlgorithm, "EC P-256")
        XCTAssertEqual(c.keyBits, 256)
        XCTAssertEqual(c.signatureAlgorithm, "ecdsa-with-SHA256")
        XCTAssertEqual(c.subjectAltNames, ["ec.example.org"])
        XCTAssertEqual(c.validityDays, 30)
        XCTAssertTrue(c.isCA)   // openssl req -x509 emits basicConstraints CA:TRUE by default (verified with openssl x509 -text)
    }

    func testGarbageDoesNotCrash() {
        XCTAssertNil(X509.parse(der: Data()))
        XCTAssertNil(X509.parse(der: Data([0x30, 0x82, 0xFF, 0xFF, 0x01])))
        XCTAssertNil(X509.parse(der: Data(repeating: 0xFF, count: 64)))
        var truncated = Self.rsaDER
        truncated.removeLast(300)
        XCTAssertNil(X509.parse(der: truncated))
    }

    func testHostnameMatching() {
        XCTAssertTrue(X509.hostMatches("a.example.com", names: ["*.example.com"]))
        XCTAssertFalse(X509.hostMatches("a.b.example.com", names: ["*.example.com"]))
        XCTAssertFalse(X509.hostMatches("example.com", names: ["*.example.com"]))
        XCTAssertTrue(X509.hostMatches("EXAMPLE.com", names: ["example.com"]))
        XCTAssertFalse(X509.hostMatches("evil.com", names: ["example.com"]))
    }

    func testTLSAnalysisFlagsProblems() throws {
        let c = try XCTUnwrap(X509.parse(der: Self.rsaDER))
        let snap = TLSSnapshot(host: "other.example.net", port: 443, negotiatedVersion: "TLS 1.3", cipher: "TLS_AES_256_GCM_SHA384", alpn: "h2",
                               chain: [c], trusted: false, trustError: "self signed",
                               protocolSupport: [("TLS 1.0", true), ("TLS 1.3", true)])
        let out = TLSAnalysis.output(snap)
        let titles = out.findings.map(\.title).joined(separator: "\n")
        XCTAssertTrue(titles.contains("Untrusted certificate"))
        XCTAssertTrue(titles.contains("Self-signed"))
        XCTAssertTrue(titles.contains("name mismatch"))
        XCTAssertTrue(titles.contains("TLS 1.0 enabled"))
    }
}
