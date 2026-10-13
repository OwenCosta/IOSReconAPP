import XCTest
@testable import ReconCore

final class TargetTests: XCTestCase {
    func testIPv4ParseRoundTrip() {
        XCTAssertEqual(IPv4.parse("192.168.1.10"), 0xC0A8010A)
        XCTAssertEqual(IPv4.string(0xC0A8010A), "192.168.1.10")
        XCTAssertNil(IPv4.parse("256.1.1.1"))
        XCTAssertNil(IPv4.parse("1.2.3"))
        XCTAssertNil(IPv4.parse("1.2.3.4.5"))
        XCTAssertNil(IPv4.parse("a.b.c.d"))
    }

    func testPrivateRanges() {
        XCTAssertTrue(IPv4.isPrivate(IPv4.parse("10.0.0.1")!))
        XCTAssertTrue(IPv4.isPrivate(IPv4.parse("172.16.5.5")!))
        XCTAssertFalse(IPv4.isPrivate(IPv4.parse("172.32.0.1")!))
        XCTAssertTrue(IPv4.isPrivate(IPv4.parse("192.168.0.1")!))
        XCTAssertFalse(IPv4.isPrivate(IPv4.parse("8.8.8.8")!))
    }

    func testSubnetMath() {
        let s = Subnet(cidr: "192.168.1.77/24")!
        XCTAssertEqual(IPv4.string(s.network), "192.168.1.0")
        XCTAssertEqual(IPv4.string(s.broadcast), "192.168.1.255")
        XCTAssertEqual(s.usableHosts, 254)
        XCTAssertEqual(s.hostAddresses().count, 254)
        XCTAssertEqual(s.hostAddresses().first, "192.168.1.1")
        XCTAssertEqual(s.hostAddresses().last, "192.168.1.254")
        XCTAssertEqual(Subnet(cidr: "10.0.0.0/30")!.usableHosts, 2)
        XCTAssertEqual(Subnet(cidr: "10.0.0.5/32")!.hostAddresses(), ["10.0.0.5"])
        XCTAssertEqual(Subnet(cidr: "10.0.0.0/31")!.hostAddresses().count, 2)
        XCTAssertNil(Subnet(cidr: "10.0.0.0/33"))
        XCTAssertTrue(Subnet(cidr: "10.0.0.0/8")!.contains(IPv4.parse("10.200.1.1")!))
    }

    func testExpandTargets() throws {
        XCTAssertEqual(try TargetParser.expand("10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])
        XCTAssertEqual(try TargetParser.expand("10.0.0.5-7"), ["10.0.0.5", "10.0.0.6", "10.0.0.7"])
        XCTAssertEqual(try TargetParser.expand("10.0.0.254-10.0.1.1").count, 4)
        XCTAssertEqual(try TargetParser.expand("Example.COM, https://example.com/path , 1.1.1.1"), ["example.com", "1.1.1.1"])
        XCTAssertEqual(try TargetParser.expand("https://user@host.example.com:8443/x?y=1"), ["host.example.com"])
        XCTAssertThrowsError(try TargetParser.expand("10.0.0.0/8"))
        XCTAssertThrowsError(try TargetParser.expand("bad host!"))
        XCTAssertThrowsError(try TargetParser.expand("   "))
        XCTAssertThrowsError(try TargetParser.expand("10.0.0.9-3"))
    }

    func testDomainExtraction() {
        XCTAssertEqual(TargetParser.domain(from: "https://WWW.Example.com/a"), "www.example.com")
        XCTAssertNil(TargetParser.domain(from: "8.8.8.8"))
        XCTAssertNil(TargetParser.domain(from: "localhost"))
        XCTAssertNil(TargetParser.domain(from: "-bad-.com"))
    }

    func testPortSpec() throws {
        XCTAssertEqual(try PortSpec.parse("22,80,443"), [22, 80, 443])
        XCTAssertEqual(try PortSpec.parse("8000-8003,22"), [22, 8000, 8001, 8002, 8003])
        XCTAssertEqual(try PortSpec.parse("top100").count, Set(ServiceDB.top100).count)
        XCTAssertEqual(try PortSpec.parse("all").count, 65535)
        XCTAssertEqual(try PortSpec.parse("80,80,80"), [80])
        XCTAssertThrowsError(try PortSpec.parse("0"))
        XCTAssertThrowsError(try PortSpec.parse("70000"))
        XCTAssertThrowsError(try PortSpec.parse("100-50"))
        XCTAssertThrowsError(try PortSpec.parse("http"))
    }

    func testServiceDB() {
        XCTAssertEqual(ServiceDB.name(port: 22), "ssh")
        XCTAssertEqual(ServiceDB.name(port: 443), "https")
        XCTAssertEqual(ServiceDB.risk(port: 2375)?.severity, .critical)
        XCTAssertNil(ServiceDB.risk(port: 443))
        XCTAssertEqual(ServiceDB.deviceHint(openPorts: [62078]), "Apple iOS device (lockdownd / iphone-sync)")
        XCTAssertEqual(Set(ServiceDB.top100).count, ServiceDB.top100.count, "duplicate ports in top100")
    }
}
