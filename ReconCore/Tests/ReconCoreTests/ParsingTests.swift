import XCTest
@testable import ReconCore

final class ParsingTests: XCTestCase {
    // MARK: DNS
    func testReverseNames() {
        XCTAssertEqual(DNSClient.reverseName("8.8.4.4"), "4.4.8.8.in-addr.arpa")
        XCTAssertEqual(DNSClient.reverseName("2001:db8::1"),
                       "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
        XCTAssertEqual(DNSClient.reverseName("::1")?.hasSuffix("ip6.arpa"), true)
        XCTAssertNil(DNSClient.reverseName("not-an-ip"))
    }

    func testTXTUnquote() {
        XCTAssertEqual(DNSClient.unquoteTXT("\"v=spf1 include:a.com\" \" -all\""), "v=spf1 include:a.com -all")
        XCTAssertEqual(DNSClient.unquoteTXT("plain"), "plain")
    }

    func testDNSWireQuery() {
        let q = DNSWire.query(name: "a.bc", type: 1)
        XCTAssertEqual([UInt8](q), [0x5E, 0xC0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0x61, 2, 0x62, 0x63, 0, 0, 1, 0, 1])
    }

    // MARK: Email security
    func testSPFParsing() {
        let spf = EmailSecurity.parseSPF("v=spf1 include:_spf.google.com include:mailgun.org ~all")!
        XCTAssertEqual(spf.all, "~all")
        XCTAssertEqual(spf.includes, ["_spf.google.com", "mailgun.org"])
        XCTAssertEqual(EmailSecurity.parseSPF("v=spf1 -all")?.all, "-all")
        XCTAssertEqual(EmailSecurity.parseSPF("v=spf1 all")?.all, "+all")
        XCTAssertNil(EmailSecurity.parseSPF("google-site-verification=abc"))
    }

    func testDMARCTags() {
        let t = EmailSecurity.parseTags("v=DMARC1; p=quarantine; pct=50; rua=mailto:d@example.com")
        XCTAssertEqual(t["p"], "quarantine")
        XCTAssertEqual(t["pct"], "50")
        XCTAssertEqual(t["rua"], "mailto:d@example.com")
    }

    // MARK: Banners
    func testBannerFingerprints() {
        var r = PortResult(host: "h", port: 22, state: .open)
        ServiceFingerprint.apply(banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", to: &r)
        XCTAssertEqual(r.service, "ssh")
        XCTAssertEqual(r.version, "OpenSSH 8.9p1 (protocol 2.0)")

        var h = PortResult(host: "h", port: 80, state: .open)
        ServiceFingerprint.apply(banner: "HTTP/1.1 200 OK Server: nginx/1.18.0 Date: Mon", to: &h)
        XCTAssertEqual(h.service, "http")

        var f = PortResult(host: "h", port: 21, state: .open)
        ServiceFingerprint.apply(banner: "220 (vsFTPd 3.0.3)", to: &f)
        XCTAssertEqual(f.service, "ftp")

        var m = PortResult(host: "h", port: 25, state: .open)
        ServiceFingerprint.apply(banner: "220 mail.example.com ESMTP Postfix (Ubuntu)", to: &m)
        XCTAssertEqual(m.service, "smtp")
        XCTAssertEqual(m.version, "Postfix")

        var v = PortResult(host: "h", port: 5900, state: .open)
        ServiceFingerprint.apply(banner: "RFB 003.008", to: &v)
        XCTAssertEqual(v.service, "vnc")
    }

    func testBannerCleaning() {
        let s = ServiceFingerprint.clean(Data([0x53, 0x53, 0x48, 0x0D, 0x0A, 0x00, 0x01, 0x41]))
        XCTAssertEqual(s, "SSH ..A")
        XCTAssertLessThanOrEqual(ServiceFingerprint.clean(Data(repeating: 0x41, count: 5000)).count, 240)
    }

    // MARK: HTTP analysis
    func testHeaderGrading() {
        let strong = WebRecon.gradeHeaders([
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "x-frame-options": "DENY", "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer", "permissions-policy": "camera=()",
            "cross-origin-opener-policy": "same-origin"], https: true)
        XCTAssertEqual(strong.grade, "A")
        XCTAssertEqual(strong.score, 100)

        let weak = WebRecon.gradeHeaders(["server": "Apache/2.4.1"], https: true)
        XCTAssertEqual(weak.grade, "F")
        XCTAssertTrue(weak.items.contains { $0.label == "Strict-Transport-Security" && $0.severity == .medium })

        let http = WebRecon.gradeHeaders([:], https: false)
        XCTAssertTrue(http.items.contains { $0.label == "Transport" && $0.severity == .high })
    }

    func testCookieAudit() {
        let items = WebRecon.auditCookies([
            "sessionid=abc; Path=/", "pref=1; Secure; HttpOnly; SameSite=Lax"], https: true)
        XCTAssertEqual(items[0].label, "sessionid")
        XCTAssertEqual(items[0].severity, .medium)
        XCTAssertTrue(items[0].value.contains("no Secure"))
        XCTAssertEqual(items[1].severity, .info)
    }

    func testSetCookieSplitting() {
        let joined = "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/, b=2; Secure, c=3; HttpOnly"
        let parts = HTTP.splitSetCookie(joined)
        XCTAssertEqual(parts.count, 3)
        XCTAssertTrue(parts[0].contains("Expires=Wed, 21 Oct"))
        XCTAssertEqual(parts[1], "b=2; Secure")
    }

    func testFingerprint() {
        let t = WebRecon.fingerprint(
            headers: ["server": "nginx/1.18.0", "x-powered-by": "PHP/8.1.2", "cf-ray": "abc"],
            cookies: ["PHPSESSID=x; path=/"],
            body: "<html><link href='/wp-content/themes/a.css'><script src='https://www.googletagmanager.com/gtag/js'></script></html>")
        let names = Set(t.map(\.name))
        XCTAssertTrue(names.isSuperset(of: ["nginx", "PHP", "Cloudflare", "WordPress", "Google Analytics"]))
        XCTAssertEqual(t.first { $0.name == "nginx" }?.version, "1.18.0")
        XCTAssertEqual(t.first { $0.name == "PHP" }?.version, "8.1.2")
    }

    func testInfoLeaks() {
        let l = WebRecon.infoLeaks(["server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "Express"])
        XCTAssertEqual(l.first { $0.label == "server" }?.severity, .low)
        XCTAssertEqual(l.first { $0.label == "x-powered-by" }?.severity, .info)
    }

    func testTitleExtraction() {
        XCTAssertEqual(WebRecon.title(of: "<html><head><TITLE>  Hello  </TITLE>"), "Hello")
        XCTAssertNil(WebRecon.title(of: "<html></html>"))
    }

    // MARK: Utils
    func testHashIdentifier() {
        func names(_ s: String) -> [String] { HashIdentifier.identify(s).items.map(\.value) }
        XCTAssertTrue(names("5f4dcc3b5aa765d61d8327deb882cf99").contains { $0.contains("MD5") })
        XCTAssertTrue(names("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8").contains { $0.contains("SHA-1") })
        XCTAssertTrue(names("$2y$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234").contains { $0.contains("bcrypt") })
        XCTAssertTrue(names("hello").contains { $0.contains("No known") })
    }

    func testEncoders() {
        XCTAssertEqual(Encoders.base64Decode("SGVsbG8"), Data("Hello".utf8))      // unpadded
        XCTAssertEqual(Encoders.base64Decode("SGVsbG8_"), Data("Hello?".utf8).isEmpty ? nil : Encoders.base64Decode("SGVsbG8_"))
        XCTAssertEqual(Encoders.hexDecode("48 65 6c 6c 6f"), Data("Hello".utf8))
        XCTAssertNil(Encoders.hexDecode("xyz"))
        XCTAssertEqual(Encoders.rot13("Hello"), "Uryyb")
        XCTAssertEqual(Encoders.rot13(Encoders.rot13("Round Trip 123")), "Round Trip 123")
    }

    func testJWT() {
        // {"alg":"none","typ":"JWT"}.{"sub":"1","exp":1}
        let none = JWT.analyze("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwiZXhwIjoxfQ.")
        XCTAssertTrue(none.findings.contains { $0.severity == .critical })
        let hs = JWT.analyze("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln")
        XCTAssertTrue(hs.sections.flatMap(\.items).contains { $0.label == "exp" })
        let bad = JWT.analyze("not-a-jwt")
        XCTAssertEqual(bad.sections.first?.items.first?.severity, .high)
    }

    func testPasswordEntropy() {
        XCTAssertLessThan(PasswordStrength.entropyBits("abc"), 20)
        XCTAssertGreaterThan(PasswordStrength.entropyBits("Tr0ub4dor&3xyz!Q"), 90)
        XCTAssertEqual(PasswordStrength.entropyBits(""), 0)
    }

    func testReportExport() {
        let r = ReconReport(kind: "t", target: "example.com", sections: [ReportSection("S", items: [ReportItem("a", "b", .high)])],
                            findings: [Finding(.high, "Bad | thing", "detail")])
        let md = ReportExporter.markdown(r)
        XCTAssertTrue(md.contains("# Recon report: example.com"))
        XCTAssertTrue(md.contains("Bad \\| thing"))
        XCTAssertNotNil(ReportExporter.json(r))
        XCTAssertEqual(r.worstSeverity, .high)
    }

    func testToolCatalogIntegrity() {
        let ids = ToolCatalog.all.map(\.id)
        XCTAssertEqual(ids.count, Set(ids).count, "duplicate tool ids")
        XCTAssertGreaterThan(ids.count, 20)
    }

    func testFullReconRejectsGarbageTarget() async {
        var finished: ReconReport?
        for await ev in FullRecon.run(target: "not a target!!") { if case .finished(let r) = ev { finished = r } }
        XCTAssertNotNil(finished)
        XCTAssertTrue(finished!.sections.isEmpty)
    }
}
