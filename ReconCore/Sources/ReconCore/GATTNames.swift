import Foundation

/// Human names for common Bluetooth SIG assigned GATT services, characteristics
/// and company identifiers — so the BLE explorer reads like nRF Connect instead
/// of a wall of UUIDs. A curated, offline subset of the most-seen numbers.
public enum GATTNames {
    public static let services: [String: String] = [
        "1800": "Generic Access", "1801": "Generic Attribute", "1802": "Immediate Alert",
        "1803": "Link Loss", "1804": "Tx Power", "1805": "Current Time Service",
        "1808": "Glucose", "1809": "Health Thermometer", "180A": "Device Information",
        "180D": "Heart Rate", "180E": "Phone Alert Status", "180F": "Battery",
        "1810": "Blood Pressure", "1811": "Alert Notification", "1812": "Human Interface Device",
        "1813": "Scan Parameters", "1814": "Running Speed and Cadence", "1816": "Cycling Speed and Cadence",
        "1818": "Cycling Power", "1819": "Location and Navigation", "181A": "Environmental Sensing",
        "181B": "Body Composition", "181C": "User Data", "181D": "Weight Scale",
        "181E": "Bond Management", "181F": "Continuous Glucose Monitoring", "1820": "Internet Protocol Support",
        "1821": "Indoor Positioning", "1822": "Pulse Oximeter", "1826": "Fitness Machine",
        "183A": "Insulin Delivery", "FE59": "Nordic DFU", "FEAA": "Eddystone",
        "FD6F": "Exposure Notification", "FDA50693": "Nordic UART (base)",
    ]

    public static let characteristics: [String: String] = [
        "2A00": "Device Name", "2A01": "Appearance", "2A02": "Peripheral Privacy Flag",
        "2A04": "Preferred Connection Parameters", "2A05": "Service Changed", "2A06": "Alert Level",
        "2A07": "Tx Power Level", "2A19": "Battery Level", "2A23": "System ID",
        "2A24": "Model Number", "2A25": "Serial Number", "2A26": "Firmware Revision",
        "2A27": "Hardware Revision", "2A28": "Software Revision", "2A29": "Manufacturer Name",
        "2A2B": "Current Time", "2A37": "Heart Rate Measurement", "2A38": "Body Sensor Location",
        "2A1C": "Temperature Measurement", "2A6E": "Temperature", "2A6F": "Humidity",
        "2A6D": "Pressure", "2A63": "Cycling Power Measurement", "2A5B": "CSC Measurement",
        "2A53": "RSC Measurement", "2A58": "Analog", "2A56": "Digital",
        "2A35": "Blood Pressure Measurement", "2A49": "Blood Pressure Feature",
        "2A9C": "Body Composition Measurement", "2A9D": "Weight Measurement", "2A8A": "First Name",
    ]

    public static let companies: [UInt16: String] = [
        0x004C: "Apple", 0x0006: "Microsoft", 0x00E0: "Google", 0x0075: "Samsung",
        0x0059: "Nordic Semiconductor", 0x000F: "Broadcom", 0x0117: "Garmin", 0x0157: "Huami/Amazfit",
        0x038F: "Xiaomi", 0x0171: "Amazon", 0x004F: "Logitech", 0x02E5: "Espressif",
        0x0201: "Fitbit", 0x00D7: "Qualcomm", 0x0310: "Tile", 0x0087: "Garmin",
        0x0030: "ST Microelectronics", 0x0499: "Ruuvi", 0x05A7: "Sonos", 0x0A05: "Shelly",
    ]

    /// Normalise a CBUUID-style string to the SIG short form when it is a 16/32-bit
    /// assigned number expressed in the Bluetooth base UUID.
    public static func normalize(_ uuid: String) -> String {
        let u = uuid.uppercased()
        if u.count == 36, u.hasSuffix("-0000-1000-8000-00805F9B34FB"), u.hasPrefix("0000") {
            return String(u.dropFirst(4).prefix(4))
        }
        return u
    }

    public static func service(_ uuid: String) -> String? { services[normalize(uuid)] }
    public static func characteristic(_ uuid: String) -> String? { characteristics[normalize(uuid)] }
    public static func company(_ id: UInt16) -> String { companies[id] ?? String(format: "0x%04X", id) }

    /// A friendly label for a UUID, falling back to the (short) UUID itself.
    public static func label(for uuid: String) -> String {
        let short = normalize(uuid)
        return services[short] ?? characteristics[short] ?? short
    }
}
