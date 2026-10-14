import XCTest
@testable import ReconCore

final class ONVIFDiscoveryTests: XCTestCase {
    let sample = """
    <?xml version="1.0" encoding="UTF-8"?>
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
    <SOAP-ENV:Header>
    <wsa:MessageID>uuid:3cb3a6d8-aaaa-bbbb-cccc-000000000001</wsa:MessageID>
    <wsa:Action SOAP-ENV:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
    <wsdd:ProbeMatches>
    <wsdd:ProbeMatch>
    <wsa:EndpointReference><wsa:Address>urn:uuid:4d454930-0000-1000-8000-ac1f09a4b2c1</wsa:Address></wsa:EndpointReference>
    <wsdd:Types>dn:NetworkVideoTransmitter</wsdd:Types>
    <wsdd:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/hardware/IPC-HDW onvif://www.onvif.org/name/Hikvision%20IPC onvif://www.onvif.org/location/unknown</wsdd:Scopes>
    <wsdd:XAddrs>http://192.168.1.64/onvif/device_service</wsdd:XAddrs>
    <wsdd:MetadataVersion>1</wsdd:MetadataVersion>
    </wsdd:ProbeMatch>
    </wsdd:ProbeMatches>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
    """

    func testParseProbeMatchExtractsXAddrsTypesScopes() {
        let d = ONVIFDiscovery.parseProbeMatch(sample)
        XCTAssertNotNil(d)
        XCTAssertEqual(d?.xaddrs, ["http://192.168.1.64/onvif/device_service"])
        XCTAssertEqual(d?.types, ["dn:NetworkVideoTransmitter"])
        XCTAssertEqual(d?.scopes.count, 4)
    }

    func testParseProbeMatchDerivesHost() {
        let d = ONVIFDiscovery.parseProbeMatch(sample)
        XCTAssertEqual(d?.host, "192.168.1.64")
    }

    func testParseProbeMatchIsLikelyCamera() {
        let d = ONVIFDiscovery.parseProbeMatch(sample)
        XCTAssertEqual(d?.isLikelyCamera, true)
    }

    func testFriendlyInfoDecodesPercentEncodedName() {
        let d = ONVIFDiscovery.parseProbeMatch(sample)
        XCTAssertEqual(d?.name, "Hikvision IPC")
        XCTAssertEqual(d?.hardware, "IPC-HDW")
        XCTAssertEqual(d?.location, "unknown")
    }

    func testParseNonProbeMatchReturnsNil() {
        XCTAssertNil(ONVIFDiscovery.parseProbeMatch("<Envelope><Body>Hello</Body></Envelope>"))
    }

    func testParseProbeMatchWithEmptyXAddrsReturnsNil() {
        let xml = "<ProbeMatches><ProbeMatch><XAddrs></XAddrs></ProbeMatch></ProbeMatches>"
        XCTAssertNil(ONVIFDiscovery.parseProbeMatch(xml))
    }

    func testMultipleXAddrsAndScopesSplit() {
        let xml = """
        <ProbeMatches><ProbeMatch>
        <Types>dn:NetworkVideoTransmitter tds:Device</Types>
        <Scopes>onvif://www.onvif.org/name/Cam1 onvif://www.onvif.org/hardware/HW1</Scopes>
        <XAddrs>http://10.0.0.5/onvif/device_service http://[fe80::1]/onvif/device_service</XAddrs>
        </ProbeMatch></ProbeMatches>
        """
        let d = ONVIFDiscovery.parseProbeMatch(xml)
        XCTAssertEqual(d?.xaddrs.count, 2)
        XCTAssertEqual(d?.types.count, 2)
        XCTAssertEqual(d?.name, "Cam1")
    }

    func testProbeMessageContainsTypeAndIsWellFormedEnoughToContainProbe() {
        let msg = ONVIFDiscovery.probeMessage(types: "dn:NetworkVideoTransmitter", messageID: "fixed-id")
        XCTAssertTrue(msg.contains("dn:NetworkVideoTransmitter"))
        XCTAssertTrue(msg.contains("uuid:fixed-id"))
        XCTAssertTrue(msg.contains("<d:Probe>"))
    }

    func testProbeMessageWithNilTypesIsGeneric() {
        let msg = ONVIFDiscovery.probeMessage(types: nil, messageID: "fixed-id")
        XCTAssertFalse(msg.contains("NetworkVideoTransmitter"))
        XCTAssertTrue(msg.contains("<d:Probe></d:Probe>") || msg.contains("<d:Probe>\n</d:Probe>"))
    }

    func testFriendlyInfoIgnoresNonOnvifScopes() {
        let (name, hw, loc) = ONVIFDiscovery.friendlyInfo(from: ["http://example.com/not-onvif", "onvif://www.onvif.org/name/OK"])
        XCTAssertEqual(name, "OK")
        XCTAssertNil(hw)
        XCTAssertNil(loc)
    }
}
