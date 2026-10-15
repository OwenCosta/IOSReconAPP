import Foundation
import SwiftUI
import ReconCore
#if canImport(CoreBluetooth)
import CoreBluetooth
#endif

/// An nRF Connect–style BLE engine: live discovery with rich advertising data,
/// device classification, and connect → GATT service/characteristic exploration.
final class BLEScanner: NSObject, ObservableObject {
    struct AdvPair: Identifiable { let id = UUID(); let key: String; let value: String }

    struct Device: Identifiable {
        let id: UUID
        var name: String
        var rssi: Int
        var services: [String]
        var vendor: String?
        var connectable: Bool
        var txPower: Int?
        var manufacturerHex: String?
        var rawAdv: [AdvPair]
        var lastSeen: Date
        var category: String
        var categoryIcon: String
        var isCamera: Bool
        var note: String?
        var hasName: Bool
        var signalBars: Int {           // 1–4 from RSSI (higher = closer)
            if rssi < -90 { return 1 }
            if rssi < -75 { return 2 }
            if rssi < -60 { return 3 }
            return 4
        }
    }

    enum State: Equatable { case unknown, unauthorized, poweredOff, unsupported, scanning, stopped }
    enum ConnState: Equatable { case disconnected, connecting, connected, failed(String) }

    struct GATTChar: Identifiable {
        let id = UUID(); let uuid: String; let name: String; let props: [String]
        var valueHex: String?; var valueText: String?
        var isNotifying: Bool = false
        var lastError: String? = nil
        var canWrite: Bool { props.contains("write") || props.contains("writeNR") }
        var canNotify: Bool { props.contains("notify") || props.contains("indicate") }
    }
    struct GATTService: Identifiable { let id = UUID(); let uuid: String; let name: String; var chars: [GATTChar] }

    @Published var devices: [Device] = []
    @Published var state: State = .unknown
    @Published var connState: ConnState = .disconnected
    @Published var connectedID: UUID?
    @Published var profile: [GATTService] = []

    var cameraCount: Int { devices.filter(\.isCamera).count }

    #if canImport(CoreBluetooth)
    private var central: CBCentralManager?
    private var seen: [UUID: Device] = [:]
    private var peripherals: [UUID: CBPeripheral] = [:]
    /// Live CBCharacteristic refs, keyed by "serviceUUID|charUUID", so the UI (which only
    /// sees value-type GATTChar/GATTService) can still trigger read/write/notify.
    private var charRefs: [String: CBCharacteristic] = [:]
    #endif

    // MARK: Scanning

    func start() {
        #if canImport(CoreBluetooth)
        if central == nil { central = CBCentralManager(delegate: self, queue: nil) }
        else { beginScan() }
        #else
        state = .unsupported
        #endif
    }

    func stop() {
        #if canImport(CoreBluetooth)
        central?.stopScan()
        #endif
        if state == .scanning { state = .stopped }
    }

    func toggleScan() { state == .scanning ? stop() : start() }

    func clear() {
        #if canImport(CoreBluetooth)
        seen.removeAll()
        #endif
        devices = []
    }

    // MARK: Connect / GATT

    func connect(_ id: UUID) {
        #if canImport(CoreBluetooth)
        guard let central, let p = peripherals[id] else { return }
        central.stopScan()
        if state == .scanning { state = .stopped }
        profile = []
        charRefs.removeAll()
        connectedID = id
        connState = .connecting
        p.delegate = self
        central.connect(p, options: nil)
        #endif
    }

    func disconnect() {
        #if canImport(CoreBluetooth)
        if let id = connectedID, let p = peripherals[id] { central?.cancelPeripheralConnection(p) }
        charRefs.removeAll()
        #endif
        connState = .disconnected
        connectedID = nil
        profile = []
    }

    // MARK: Read / write / notify

    #if canImport(CoreBluetooth)
    private static func key(_ service: String, _ char: String) -> String { "\(service)|\(char)" }

    private var connectedPeripheral: CBPeripheral? { connectedID.flatMap { peripherals[$0] } }

    func readCharacteristic(service: String, char: String) {
        guard let p = connectedPeripheral, let c = charRefs[Self.key(service, char)] else { return }
        p.readValue(for: c)
    }

    /// Write a hex-encoded value (e.g. "01 FF" or "01FF") to a writable characteristic.
    func writeCharacteristic(service: String, char: String, hex: String, withResponse: Bool) {
        guard let p = connectedPeripheral, let c = charRefs[Self.key(service, char)] else { return }
        guard let data = Encoders.hexDecode(hex) else {
            setChar(service, char) { $0.lastError = "Invalid hex. Use pairs like 01 A4 FF" }
            return
        }
        p.writeValue(data, for: c, type: withResponse ? .withResponse : .withoutResponse)
        if !withResponse {
            // No write-confirmation callback arrives for .withoutResponse; reflect it immediately.
            setChar(service, char) { $0.valueHex = BLEScanner.hex(data); $0.valueText = BLEScanner.printable(data); $0.lastError = nil }
        }
    }

    func toggleNotify(service: String, char: String) {
        guard let p = connectedPeripheral, let c = charRefs[Self.key(service, char)] else { return }
        let turningOn = !(profileChar(service, char)?.isNotifying ?? false)
        p.setNotifyValue(turningOn, for: c)
    }

    private func profileChar(_ service: String, _ char: String) -> GATTChar? {
        guard let si = profile.firstIndex(where: { $0.uuid == service }) else { return nil }
        return profile[si].chars.first { $0.uuid == char }
    }

    private func setChar(_ service: String, _ char: String, _ mutate: (inout GATTChar) -> Void) {
        guard let si = profile.firstIndex(where: { $0.uuid == service }),
              let ci = profile[si].chars.firstIndex(where: { $0.uuid == char }) else { return }
        mutate(&profile[si].chars[ci])
    }
    #endif

    #if canImport(CoreBluetooth)
    private func beginScan() {
        guard let central, central.state == .poweredOn else { return }
        state = .scanning
        central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
    }
    private func publish() { devices = seen.values.sorted { $0.rssi > $1.rssi } }

    static func hex(_ data: Data, sep: String = " ") -> String { data.map { String(format: "%02X", $0) }.joined(separator: sep) }
    static func printable(_ data: Data) -> String? {
        guard let s = String(data: data, encoding: .utf8), s.allSatisfy({ $0.isASCII && (!$0.isNewline) }), !s.isEmpty else { return nil }
        return s.allSatisfy { $0.asciiValue.map { $0 >= 0x20 && $0 < 0x7F } ?? false } ? s : nil
    }
    #endif
}

#if canImport(CoreBluetooth)
extension BLEScanner: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn: beginScan()
        case .poweredOff: state = .poweredOff
        case .unauthorized: state = .unauthorized
        case .unsupported: state = .unsupported
        default: state = .unknown
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let id = peripheral.identifier
        peripherals[id] = peripheral

        let advName = advertisementData[CBAdvertisementDataLocalNameKey] as? String
        let name = advName ?? peripheral.name ?? "Unknown"
        let hasName = (advName ?? peripheral.name) != nil

        var services: [String] = []
        if let uuids = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] { services = uuids.map { $0.uuidString } }

        var vendor: String?
        var manHex: String?
        if let mfg = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data, mfg.count >= 2 {
            let company = UInt16(mfg[0]) | (UInt16(mfg[1]) << 8)
            vendor = GATTNames.company(company)
            manHex = BLEScanner.hex(mfg)
        }
        let txPower = (advertisementData[CBAdvertisementDataTxPowerLevelKey] as? NSNumber)?.intValue
        let connectable = (advertisementData[CBAdvertisementDataIsConnectable] as? NSNumber)?.boolValue ?? false

        // Full advertising breakdown (nRF Connect style).
        var raw: [AdvPair] = []
        if let advName { raw.append(.init(key: "Local Name", value: advName)) }
        if let v = vendor { raw.append(.init(key: "Manufacturer", value: v)) }
        if let h = manHex { raw.append(.init(key: "Manufacturer Data", value: h)) }
        if !services.isEmpty { raw.append(.init(key: "Service UUIDs", value: services.map { GATTNames.label(for: $0) }.joined(separator: ", "))) }
        if let sd = advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data] {
            for (u, d) in sd { raw.append(.init(key: "Service Data \(GATTNames.label(for: u.uuidString))", value: BLEScanner.hex(d))) }
        }
        if let tx = txPower { raw.append(.init(key: "Tx Power", value: "\(tx) dBm")) }
        raw.append(.init(key: "Connectable", value: connectable ? "Yes" : "No"))

        let k = BLEClassifier.classify(name: name, vendor: vendor, serviceUUIDs: services)
        seen[id] = Device(id: id, name: name, rssi: RSSI.intValue, services: services, vendor: vendor,
                          connectable: connectable, txPower: txPower, manufacturerHex: manHex, rawAdv: raw,
                          lastSeen: Date(), category: k.category, categoryIcon: k.icon, isCamera: k.isCamera,
                          note: k.note, hasName: hasName)
        publish()
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connState = .connected
        peripheral.discoverServices(nil)
    }
    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        connState = .failed(error?.localizedDescription ?? "connection failed")
    }
    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if connState == .connected { connState = .disconnected }
    }
}

extension BLEScanner: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let services = peripheral.services else { return }
        profile = services.map { GATTService(uuid: $0.uuid.uuidString, name: GATTNames.label(for: $0.uuid.uuidString), chars: []) }
        for s in services { peripheral.discoverCharacteristics(nil, for: s) }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let chars = service.characteristics else { return }
        let entries: [GATTChar] = chars.map { c in
            var props: [String] = []
            let p = c.properties
            if p.contains(.read) { props.append("read") }
            if p.contains(.write) { props.append("write") }
            if p.contains(.writeWithoutResponse) { props.append("writeNR") }
            if p.contains(.notify) { props.append("notify") }
            if p.contains(.indicate) { props.append("indicate") }
            return GATTChar(uuid: c.uuid.uuidString, name: GATTNames.label(for: c.uuid.uuidString), props: props, valueHex: nil, valueText: nil)
        }
        if let i = profile.firstIndex(where: { $0.uuid == service.uuid.uuidString }) {
            profile[i].chars = entries
        }
        for c in chars { charRefs[Self.key(service.uuid.uuidString, c.uuid.uuidString)] = c }
        // Auto-read readable characteristics.
        for c in chars where c.properties.contains(.read) { peripheral.readValue(for: c) }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let si = profile.firstIndex(where: { $0.chars.contains { $0.uuid == characteristic.uuid.uuidString } }),
              let ci = profile[si].chars.firstIndex(where: { $0.uuid == characteristic.uuid.uuidString }) else { return }
        if let error {
            profile[si].chars[ci].lastError = error.localizedDescription
            return
        }
        guard let data = characteristic.value else { return }
        profile[si].chars[ci].valueHex = BLEScanner.hex(data)
        profile[si].chars[ci].valueText = BLEScanner.printable(data)
        profile[si].chars[ci].lastError = nil
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let si = profile.firstIndex(where: { $0.chars.contains { $0.uuid == characteristic.uuid.uuidString } }),
              let ci = profile[si].chars.firstIndex(where: { $0.uuid == characteristic.uuid.uuidString }) else { return }
        if let error {
            profile[si].chars[ci].lastError = error.localizedDescription
        } else {
            profile[si].chars[ci].lastError = nil
            if let data = characteristic.value {
                profile[si].chars[ci].valueHex = BLEScanner.hex(data)
                profile[si].chars[ci].valueText = BLEScanner.printable(data)
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard let si = profile.firstIndex(where: { $0.chars.contains { $0.uuid == characteristic.uuid.uuidString } }),
              let ci = profile[si].chars.firstIndex(where: { $0.uuid == characteristic.uuid.uuidString }) else { return }
        if let error {
            profile[si].chars[ci].lastError = error.localizedDescription
        } else {
            profile[si].chars[ci].isNotifying = characteristic.isNotifying
            profile[si].chars[ci].lastError = nil
        }
    }
}
#endif
