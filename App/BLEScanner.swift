import Foundation
import SwiftUI
import ReconCore
#if canImport(CoreBluetooth)
import CoreBluetooth
#endif

/// Scans for nearby Bluetooth Low Energy devices. iOS exposes BLE (not classic
/// Bluetooth) to apps, so this discovers advertisers — wearables, beacons,
/// smart-home gear, trackers — with name, signal, services and vendor.
final class BLEScanner: NSObject, ObservableObject {
    struct Device: Identifiable {
        let id: UUID
        var name: String
        var rssi: Int
        var services: [String]
        var vendor: String?
        var connectable: Bool
        var lastSeen: Date
        var category: String
        var categoryIcon: String
        var isCamera: Bool
        var note: String?
        var signalBars: Int {           // 1–4 from RSSI (higher = closer)
            if rssi < -90 { return 1 }
            if rssi < -75 { return 2 }
            if rssi < -60 { return 3 }
            return 4
        }
    }

    enum State: Equatable { case unknown, unauthorized, poweredOff, unsupported, scanning, stopped }

    @Published var devices: [Device] = []
    @Published var state: State = .unknown

    var cameraCount: Int { devices.filter(\.isCamera).count }

    #if canImport(CoreBluetooth)
    private var central: CBCentralManager?
    private var seen: [UUID: Device] = [:]
    #endif

    /// Bluetooth SIG company identifiers (a useful subset) for manufacturer data.
    static let companies: [UInt16: String] = [
        0x004C: "Apple", 0x0006: "Microsoft", 0x00E0: "Google", 0x0075: "Samsung",
        0x0059: "Nordic", 0x000F: "Broadcom", 0x0117: "Garmin", 0x0157: "Huami/Amazfit",
        0x038F: "Xiaomi", 0x0171: "Amazon", 0x004F: "Logitech", 0x0087: "Garmin",
        0x02E5: "Espressif", 0x0201: "Fitbit", 0x00D7: "Qualcomm", 0x0310: "Tile"
    ]

    func start() {
        #if canImport(CoreBluetooth)
        if central == nil {
            central = CBCentralManager(delegate: self, queue: nil)   // nil queue → main
        } else {
            beginScan()
        }
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

    func clear() {
        #if canImport(CoreBluetooth)
        seen.removeAll()
        #endif
        devices = []
    }

    #if canImport(CoreBluetooth)
    private func beginScan() {
        guard let central, central.state == .poweredOn else { return }
        state = .scanning
        central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
    }

    private func publish() {
        devices = seen.values.sorted { $0.rssi > $1.rssi }
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
        let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String)
            ?? peripheral.name ?? "Unknown"
        var services: [String] = []
        if let uuids = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] {
            services = uuids.map { $0.uuidString }
        }
        var vendor: String?
        if let mfg = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data, mfg.count >= 2 {
            let company = UInt16(mfg[0]) | (UInt16(mfg[1]) << 8)
            vendor = BLEScanner.companies[company] ?? String(format: "0x%04X", company)
        }
        let connectable = (advertisementData[CBAdvertisementDataIsConnectable] as? NSNumber)?.boolValue ?? false
        let k = BLEClassifier.classify(name: name, vendor: vendor, serviceUUIDs: services)
        seen[id] = Device(id: id, name: name, rssi: RSSI.intValue, services: services,
                          vendor: vendor, connectable: connectable, lastSeen: Date(),
                          category: k.category, categoryIcon: k.icon, isCamera: k.isCamera, note: k.note)
        publish()
    }
}
#endif
