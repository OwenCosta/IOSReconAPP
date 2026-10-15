import Foundation

/// Classifies a BLE advertiser into a device category from its advertised name,
/// vendor and GATT service UUIDs. Lets the scanner highlight cameras and IoT
/// around you with no network connection at all.
public enum BLEClassifier {
    public enum Category: String, Sendable {
        case camera = "Camera / doorbell"
        case wearable = "Wearable / fitness"
        case audio = "Audio"
        case tracker = "Tag / tracker"
        case smartHome = "Smart home / IoT"
        case computer = "Computer / phone"
        case peripheral = "Keyboard / mouse"
        case medical = "Medical / health"
        case beacon = "Beacon"
        case unknown = "Unknown"
        public var icon: String {
            switch self {
            case .camera: return "video.fill"
            case .wearable: return "applewatch"
            case .audio: return "headphones"
            case .tracker: return "tag.fill"
            case .smartHome: return "house.fill"
            case .computer: return "desktopcomputer"
            case .peripheral: return "keyboard"
            case .medical: return "heart.fill"
            case .beacon: return "dot.radiowaves.left.and.right"
            case .unknown: return "questionmark.circle"
            }
        }
    }

    public struct Result: Equatable, Sendable {
        public let category: String
        public let icon: String
        public let isCamera: Bool
        public let note: String?
    }

    static let cameraNames = ["cam", "ipc", "camera", "doorbell", "wyze", "ring", "nest", "arlo", "reolink",
                              "tapo", "eufy", "blink", "hikvision", "dahua", "insta360", "gopro", "tplinkcam",
                              "yi ", "yicam", "foscam", "amcrest", "lorex", "swann", "vstarcam", "sricam"]
    static let wearableNames = ["watch", "band", "fit", "garmin", "whoop", "oura", "miband", "amazfit",
                                "fitbit", "versa", "charge", "polar", "wahoo", "coros"]
    static let audioNames = ["airpods", "buds", "jbl", "bose", "beats", "soundcore", "wh-", "wf-", "earbuds",
                             "headphone", "speaker", "flip", "charge 5", "pods"]
    static let trackerNames = ["tile", "airtag", "chipolo", "smarttag", "galaxy smarttag", "trackr", "find my"]
    static let smartHomeNames = ["bulb", "plug", "switch", "lock", "sensor", "thermostat", "hue", "lifx",
                                 "govee", "switchbot", "aqara", "smartthings", "kasa", "meross", "shelly",
                                 "led", "strip", "gateway", "hub"]
    static let computerNames = ["macbook", "iphone", "ipad", "galaxy", "pixel", "surface", "desktop", "laptop", "-pc"]

    /// 16-bit assigned GATT service UUIDs that strongly imply a category.
    static let serviceHints: [String: Category] = [
        "180D": .medical,   // Heart Rate
        "1810": .medical,   // Blood Pressure
        "1809": .medical,   // Health Thermometer
        "1808": .medical,   // Glucose
        "1816": .wearable,  // Cycling Speed and Cadence
        "1814": .wearable,  // Running Speed and Cadence
        "1812": .peripheral,// HID
        "FEAA": .beacon,    // Eddystone
        "FE9F": .smartHome, // Google (often Nest/home)
    ]

    public static func classify(name: String, vendor: String?, serviceUUIDs: [String]) -> Result {
        let n = name.lowercased()
        let v = (vendor ?? "").lowercased()
        let svcs = serviceUUIDs.map { normalize($0) }

        func anyName(_ list: [String]) -> Bool { list.contains { n.contains($0) } }

        if anyName(cameraNames) || v.contains("wyze") {
            return Result(category: Category.camera.rawValue, icon: Category.camera.icon, isCamera: true,
                          note: "Possible camera nearby: many cams beacon over BLE (especially in setup/pairing mode).")
        }
        if anyName(trackerNames) { return r(.tracker) }
        if anyName(audioNames) { return r(.audio) }
        if anyName(wearableNames) { return r(.wearable) }
        if anyName(smartHomeNames) { return r(.smartHome, note: "IoT device, check if it also has a web/RTSP interface once on the network.") }
        if anyName(computerNames) { return r(.computer) }

        // Service-UUID hints.
        for s in svcs { if let cat = serviceHints[s] { return r(cat) } }

        // Vendor-only hints.
        if v.contains("apple") && n.contains("unknown") { return r(.computer) }
        if v.contains("garmin") { return r(.wearable) }
        if v.contains("tile") { return r(.tracker) }

        return r(.unknown)
    }

    private static func r(_ c: Category, note: String? = nil) -> Result {
        Result(category: c.rawValue, icon: c.icon, isCamera: c == .camera, note: note)
    }

    /// Normalise a CBUUID-style string to an upper-case 16-bit short form when possible.
    static func normalize(_ uuid: String) -> String {
        let u = uuid.uppercased()
        // 128-bit base UUID 0000XXXX-0000-1000-8000-00805F9B34FB → short XXXX
        if u.count == 36, u.hasSuffix("-0000-1000-8000-00805F9B34FB"), u.hasPrefix("0000") {
            return String(u.dropFirst(4).prefix(4))
        }
        return u
    }
}
