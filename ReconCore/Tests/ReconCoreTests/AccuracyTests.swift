import XCTest
@testable import ReconCore

final class AccuracyTests: XCTestCase {
    // Fingerprint must not fire on pages that merely mention a product name.
    func testFingerprintNoFalsePositives() {
        let blog = """
        <html><head><title>Why we moved off Tailwind CSS and WooCommerce</title></head>
        <body><article>This post explains why our Squarespace migration and our old
        woocommerce store taught us about tailwind utility classes and bootstrap grids.
        We also mention react and angular in passing.</article></body></html>
        """
        let techs = WebRecon.fingerprint(headers: [:], cookies: [], body: blog).map(\.name)
        XCTAssertFalse(techs.contains("Tailwind CSS"), "false Tailwind: \(techs)")
        XCTAssertFalse(techs.contains("WooCommerce"), "false WooCommerce: \(techs)")
        XCTAssertFalse(techs.contains("Squarespace"), "false Squarespace: \(techs)")
    }

    func testFingerprintStillDetectsReal() {
        let real = """
        <html><head><script src="https://cdn.tailwindcss.com"></script>
        <link href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css"></head>
        <body data-reactroot><script src="/static/jquery-3.6.0.min.js"></script></body></html>
        """
        let techs = WebRecon.fingerprint(headers: ["server": "nginx/1.25.3"], cookies: ["PHPSESSID=x"], body: real).map(\.name)
        XCTAssertTrue(techs.contains("Tailwind CSS"))
        XCTAssertTrue(techs.contains("WooCommerce"))
        XCTAssertTrue(techs.contains("React"))
        XCTAssertTrue(techs.contains("jQuery"))
        XCTAssertTrue(techs.contains("nginx"))
    }

    // Proxy/NAT interference detection.
    func testProxyInterference() {
        func host(open: Int, closed: Int, filtered: Int) -> HostResult {
            let ports = (0..<open).map { PortResult(host: "h", port: UInt16(1000 + $0), state: .open) }
            return HostResult(host: "h", alive: true, aliveReason: "x", openPorts: ports, closedCount: closed, filteredCount: filtered, deviceHint: nil)
        }
        XCTAssertTrue(host(open: 20, closed: 0, filtered: 0).likelyProxyInterference)
        XCTAssertTrue(host(open: 95, closed: 3, filtered: 2).likelyProxyInterference)
        XCTAssertFalse(host(open: 3, closed: 95, filtered: 2).likelyProxyInterference)
        XCTAssertFalse(host(open: 5, closed: 0, filtered: 0).likelyProxyInterference) // too few to judge
    }

    // SPF with redirect= is valid, not a "no all mechanism" weakness.
    func testSPFRedirectNotFlagged() {
        XCTAssertEqual(EmailSecurity.parseSPF("v=spf1 redirect=_spf.example.com")?.all, nil)
        // parseSPF returns nil 'all' for redirect; the analyzer treats it as delegated (tested via verdict path)
    }
}
