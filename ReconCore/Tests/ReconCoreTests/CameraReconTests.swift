import XCTest
@testable import ReconCore

final class CameraReconTests: XCTestCase {

    func testIdentifyHikvisionFromServerHeader() {
        let m = CameraRecon.identify(server: "App-webs/", realm: "Basic realm=\"Hikvision\"", title: nil, body: "")
        XCTAssertEqual(m.first?.name, "Hikvision")
    }

    func testIdentifyDahuaFromBody() {
        let m = CameraRecon.identify(server: "Boa/0.94", realm: nil, title: "WEB SERVICE", body: "<html>login to dahua device /RPC2</html>")
        XCTAssertTrue(m.contains { $0.name == "Dahua / Amcrest" })
    }

    func testIdentifyUnknownReturnsEmpty() {
        let m = CameraRecon.identify(server: "nginx", realm: nil, title: "Welcome", body: "<h1>hello</h1>")
        XCTAssertTrue(m.isEmpty)
    }

    func testRTSPURLsBuildWithAuth() {
        let hik = CameraRecon.brands.first { $0.name == "Hikvision" }!
        let urls = CameraRecon.rtspURLs(host: "10.0.0.5", brand: hik, cred: ("admin", "12345"))
        XCTAssertTrue(urls.contains("rtsp://admin:12345@10.0.0.5:554/Streaming/Channels/101"))
    }

    func testRTSPURLsNoAuth() {
        let dahua = CameraRecon.brands.first { $0.name == "Dahua / Amcrest" }!
        let urls = CameraRecon.rtspURLs(host: "cam.local", brand: dahua, cred: nil)
        XCTAssertTrue(urls.contains { $0.hasPrefix("rtsp://cam.local:554/cam/realmonitor?channel=1") })
    }

    func testEveryBrandHasCredsAndRTSP() {
        for b in CameraRecon.brands {
            XCTAssertFalse(b.creds.isEmpty, "\(b.name) has no creds")
            XCTAssertFalse(b.rtsp.isEmpty, "\(b.name) has no RTSP paths")
            XCTAssertFalse(b.ports.isEmpty, "\(b.name) has no ports")
        }
    }

    func testTitleExtraction() {
        XCTAssertEqual(CameraRecon.titleOf("<html><head><TITLE>NetCam Login</TITLE></head>"), "NetCam Login")
        XCTAssertNil(CameraRecon.titleOf("<html>no title here</html>"))
    }

    func testWiFiReconHasRouterCredsAndTailoredURLs() {
        let out = WiFiRecon.run("192.168.1.1")
        let flat = out.sections.flatMap { $0.items.map { "\($0.label) \($0.value)" } }.joined(separator: "\n")
        XCTAssertTrue(flat.contains("192.168.1.1"), "gateway URLs not tailored")
        XCTAssertTrue(flat.lowercased().contains("netgear"))
        // Honest about scanning being impossible.
        XCTAssertTrue(flat.lowercased().contains("cannot"))
    }
}
