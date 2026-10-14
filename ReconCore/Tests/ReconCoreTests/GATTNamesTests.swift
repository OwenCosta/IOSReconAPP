import XCTest
@testable import ReconCore

final class GATTNamesTests: XCTestCase {
    func testServiceLookup() {
        XCTAssertEqual(GATTNames.service("180F"), "Battery")
        XCTAssertEqual(GATTNames.service("180a"), "Device Information")  // case-insensitive
    }
    func testCharacteristicLookup() {
        XCTAssertEqual(GATTNames.characteristic("2A19"), "Battery Level")
        XCTAssertEqual(GATTNames.characteristic("2A29"), "Manufacturer Name")
    }
    func testNormalize128bit() {
        XCTAssertEqual(GATTNames.normalize("0000180f-0000-1000-8000-00805f9b34fb"), "180F")
        XCTAssertEqual(GATTNames.service("0000180F-0000-1000-8000-00805F9B34FB"), "Battery")
    }
    func testLabelFallsBackToShortUUID() {
        XCTAssertEqual(GATTNames.label(for: "ABCD"), "ABCD")
        XCTAssertEqual(GATTNames.label(for: "180D"), "Heart Rate")
    }
    func testCompany() {
        XCTAssertEqual(GATTNames.company(0x004C), "Apple")
        XCTAssertEqual(GATTNames.company(0xFFFF), "0xFFFF")
    }
}
