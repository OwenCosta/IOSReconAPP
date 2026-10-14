import XCTest
@testable import ReconCore

final class BLEClassifierTests: XCTestCase {
    func testCameraByName() {
        let r = BLEClassifier.classify(name: "Wyze Cam v3", vendor: nil, serviceUUIDs: [])
        XCTAssertTrue(r.isCamera)
        XCTAssertEqual(r.category, "Camera / doorbell")
    }
    func testDoorbellByName() {
        XCTAssertTrue(BLEClassifier.classify(name: "Ring Video Doorbell", vendor: nil, serviceUUIDs: []).isCamera)
    }
    func testWearableByName() {
        XCTAssertEqual(BLEClassifier.classify(name: "Mi Band 7", vendor: nil, serviceUUIDs: []).category, "Wearable / fitness")
    }
    func testAudioByName() {
        XCTAssertEqual(BLEClassifier.classify(name: "AirPods Pro", vendor: "Apple", serviceUUIDs: []).category, "Audio")
    }
    func testTrackerByName() {
        XCTAssertEqual(BLEClassifier.classify(name: "Tile Mate", vendor: nil, serviceUUIDs: []).category, "Tag / tracker")
    }
    func testMedicalByServiceUUID() {
        let r = BLEClassifier.classify(name: "HRM-1234", vendor: nil, serviceUUIDs: ["180D"])
        XCTAssertEqual(r.category, "Medical / health")
    }
    func testServiceUUID128bitNormalises() {
        XCTAssertEqual(BLEClassifier.normalize("0000180d-0000-1000-8000-00805f9b34fb"), "180D")
        let r = BLEClassifier.classify(name: "x", vendor: nil, serviceUUIDs: ["0000180D-0000-1000-8000-00805F9B34FB"])
        XCTAssertEqual(r.category, "Medical / health")
    }
    func testUnknownFallback() {
        let r = BLEClassifier.classify(name: "XZ-9", vendor: nil, serviceUUIDs: [])
        XCTAssertEqual(r.category, "Unknown")
        XCTAssertFalse(r.isCamera)
    }
    func testSmartHomeHasNote() {
        let r = BLEClassifier.classify(name: "Govee LED Strip", vendor: nil, serviceUUIDs: [])
        XCTAssertEqual(r.category, "Smart home / IoT")
        XCTAssertNotNil(r.note)
    }
}
