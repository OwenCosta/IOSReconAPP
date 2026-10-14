import SwiftUI
import ReconCore

/// nRF Connect–style BLE scanner: live list with filtering/sorting and
/// tap-to-connect GATT exploration.
struct BLEScannerView: View {
    @StateObject private var scanner = BLEScanner()
    @State private var search = ""
    @State private var minRSSI: Double = -100
    @State private var connectableOnly = false
    @State private var namedOnly = false
    @State private var camerasOnly = false
    @State private var sort: SortMode = .rssi
    @State private var showFilters = false

    enum SortMode: String, CaseIterable, Identifiable { case rssi = "Signal", name = "Name", seen = "Last seen"; var id: String { rawValue } }

    private var filtered: [BLEScanner.Device] {
        let q = search.lowercased()
        var list = scanner.devices.filter { d in
            (Int(minRSSI) <= d.rssi) &&
            (!connectableOnly || d.connectable) &&
            (!namedOnly || d.hasName) &&
            (!camerasOnly || d.isCamera) &&
            (q.isEmpty || d.name.lowercased().contains(q) || d.category.lowercased().contains(q)
             || (d.vendor?.lowercased().contains(q) ?? false) || d.id.uuidString.lowercased().contains(q)
             || d.services.contains { $0.lowercased().contains(q) })
        }
        switch sort {
        case .rssi: list.sort { $0.rssi > $1.rssi }
        case .name: list.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        case .seen: list.sort { $0.lastSeen > $1.lastSeen }
        }
        return list
    }

    var body: some View {
        VStack(spacing: 0) {
            statusBar
            filterBar
            if filtered.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "dot.radiowaves.left.and.right").font(.system(size: 42)).foregroundStyle(Theme.dim)
                    Text(emptyText).font(.callout).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
                }.padding(40).frame(maxHeight: .infinity)
            } else {
                List {
                    if scanner.cameraCount > 0 && !camerasOnly {
                        Button { camerasOnly = true } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "video.fill").foregroundStyle(Severity.high.color)
                                Text("\(scanner.cameraCount) possible camera\(scanner.cameraCount == 1 ? "" : "s") nearby — tap to filter")
                                    .font(.caption.weight(.semibold)).foregroundStyle(Theme.fg)
                            }
                        }.listRowBackground(Severity.high.color.opacity(0.15))
                    }
                    ForEach(filtered) { d in
                        NavigationLink { BLEDeviceDetailView(scanner: scanner, deviceID: d.id, snapshot: d) } label: { row(d) }
                            .listRowBackground(Theme.card)
                    }
                }
                .scrollContentBackground(.hidden)
            }
        }
        .screenBackground()
        .navigationTitle("Bluetooth (BLE)").navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { scanner.toggleScan() } label: { Image(systemName: scanner.state == .scanning ? "pause.circle" : "play.circle") }
            }
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { scanner.clear() } label: { Image(systemName: "trash") }.disabled(scanner.devices.isEmpty)
            }
        }
        .onAppear { scanner.start() }
        .onDisappear { scanner.stop() }
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            Circle().fill(scanner.state == .scanning ? Severity.low.color : Theme.dim).frame(width: 9, height: 9)
            Text(stateText).font(.caption).foregroundStyle(Theme.dim)
            Spacer()
            Text("\(filtered.count)/\(scanner.devices.count)").font(.system(.caption, design: .monospaced)).foregroundStyle(Theme.dim)
            if scanner.state == .scanning { ProgressView().controlSize(.small) }
        }
        .padding(.horizontal, 14).padding(.vertical, 8).background(Theme.card)
    }

    private var filterBar: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").font(.caption).foregroundStyle(Theme.dim)
                    TextField("Filter name, vendor, UUID…", text: $search)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().font(.callout)
                    if !search.isEmpty { Button { search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(Theme.dim) } }
                }
                .padding(8).background(Color.black.opacity(0.3), in: RoundedRectangle(cornerRadius: 10))
                Menu {
                    Picker("Sort", selection: $sort) { ForEach(SortMode.allCases) { Text($0.rawValue).tag($0) } }
                } label: { Image(systemName: "arrow.up.arrow.down.circle").font(.title3).foregroundStyle(Theme.accent) }
                Button { withAnimation { showFilters.toggle() } } label: {
                    Image(systemName: showFilters ? "line.3.horizontal.decrease.circle.fill" : "line.3.horizontal.decrease.circle")
                        .font(.title3).foregroundStyle(anyFilterActive ? Theme.accent : Theme.dim)
                }
            }
            if showFilters {
                VStack(spacing: 8) {
                    HStack {
                        Text("Min signal").font(.caption).foregroundStyle(Theme.dim)
                        Slider(value: $minRSSI, in: -100 ... -30, step: 5)
                        Text("\(Int(minRSSI)) dBm").font(.system(.caption2, design: .monospaced)).foregroundStyle(Theme.dim).frame(width: 64, alignment: .trailing)
                    }
                    HStack(spacing: 8) {
                        chip("Connectable", $connectableOnly)
                        chip("Named", $namedOnly)
                        chip("Cameras", $camerasOnly)
                        Spacer()
                        if anyFilterActive { Button("Reset") { resetFilters() }.font(.caption).foregroundStyle(Theme.accent) }
                    }
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8).background(Theme.bg)
    }

    private var anyFilterActive: Bool { connectableOnly || namedOnly || camerasOnly || minRSSI > -100 || !search.isEmpty }
    private func resetFilters() { connectableOnly = false; namedOnly = false; camerasOnly = false; minRSSI = -100; search = "" }

    private func chip(_ label: String, _ on: Binding<Bool>) -> some View {
        Button { on.wrappedValue.toggle() } label: {
            Text(label).font(.caption.weight(.medium))
                .padding(.horizontal, 10).padding(.vertical, 5)
                .background((on.wrappedValue ? Theme.accent : Theme.raised), in: Capsule())
                .foregroundStyle(on.wrappedValue ? Color.black : Theme.fg)
        }.buttonStyle(.plain)
    }

    private func row(_ d: BLEScanner.Device) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: d.categoryIcon).foregroundStyle(d.isCamera ? Severity.high.color : (d.connectable ? Theme.accent : Theme.dim))
                Text(d.name).font(.body.weight(.semibold)).foregroundStyle(Theme.fg).lineLimit(1)
                Spacer()
                signal(d.signalBars)
                Text("\(d.rssi)").font(.system(.caption2, design: .monospaced)).foregroundStyle(Theme.dim)
            }
            HStack(spacing: 8) {
                tag(d.category, d.isCamera ? Severity.high.color : Theme.accent)
                if let v = d.vendor { tag(v, Theme.dim) }
                if d.connectable { tag("connectable", Severity.low.color) }
            }
        }.padding(.vertical, 2)
    }

    private func signal(_ bars: Int) -> some View {
        HStack(spacing: 1.5) {
            ForEach(1...4, id: \.self) { i in
                RoundedRectangle(cornerRadius: 1).fill(i <= bars ? Theme.accent : Theme.dim.opacity(0.3))
                    .frame(width: 3, height: CGFloat(4 + i * 3))
            }
        }
    }
    private func tag(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 10, weight: .medium)).padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.18), in: Capsule()).foregroundStyle(color)
    }

    private var stateText: String {
        switch scanner.state {
        case .unknown: return "Starting…"; case .scanning: return "Scanning"
        case .stopped: return "Paused"; case .poweredOff: return "Bluetooth off"
        case .unauthorized: return "Allow Bluetooth in Settings"; case .unsupported: return "BLE unavailable"
        }
    }
    private var emptyText: String {
        if anyFilterActive && !scanner.devices.isEmpty { return "No devices match the filter." }
        switch scanner.state {
        case .poweredOff: return "Bluetooth is off. Turn it on in Control Centre."
        case .unauthorized: return "Enable Bluetooth in Settings › Privacy & Security › Bluetooth."
        case .unsupported: return "This device can't scan BLE."
        default: return "Listening for nearby Bluetooth Low Energy devices…"
        }
    }
}

/// Per-device detail: full advertising data + connect → GATT services/characteristics.
struct BLEDeviceDetailView: View {
    @ObservedObject var scanner: BLEScanner
    let deviceID: UUID
    let snapshot: BLEScanner.Device

    private var device: BLEScanner.Device { scanner.devices.first { $0.id == deviceID } ?? snapshot }
    private var isConnectedHere: Bool { scanner.connectedID == deviceID }

    var body: some View {
        List {
            Section {
                row("Category", device.category)
                row("Signal", "\(device.rssi) dBm")
                if let v = device.vendor { row("Vendor", v) }
                if let tx = device.txPower { row("Tx Power", "\(tx) dBm") }
                row("Connectable", device.connectable ? "Yes" : "No")
                row("Identifier", device.id.uuidString, mono: true)
                if let note = device.note { Text(note).font(.caption).foregroundStyle(Theme.dim).listRowBackground(Theme.card) }
            } header: { Text(device.name).foregroundStyle(Theme.accent) }

            Section("Advertising data") {
                ForEach(device.rawAdv) { p in row(p.key, p.value, mono: p.key.contains("Data")) }
            }

            if device.connectable {
                Section {
                    connectRow
                    ForEach(scanner.profile) { s in serviceBlock(s) }
                } header: { Text("GATT").foregroundStyle(Theme.accent) }
            }
        }
        .scrollContentBackground(.hidden).screenBackground()
        .navigationTitle(device.name).navigationBarTitleDisplayMode(.inline)
        .onDisappear { if isConnectedHere { scanner.disconnect() } }
    }

    @ViewBuilder private var connectRow: some View {
        HStack {
            switch scanner.connState {
            case .connected where isConnectedHere:
                Label("Connected", systemImage: "link").foregroundStyle(Severity.low.color)
                Spacer()
                Button("Disconnect") { scanner.disconnect() }.foregroundStyle(Severity.high.color)
            case .connecting where isConnectedHere:
                ProgressView().controlSize(.small); Text("Connecting…").foregroundStyle(Theme.dim)
            case .failed(let m) where isConnectedHere:
                Text(m).font(.caption).foregroundStyle(Severity.high.color)
                Spacer(); Button("Retry") { scanner.connect(deviceID) }.foregroundStyle(Theme.accent)
            default:
                Button { scanner.connect(deviceID) } label: { Label("Connect & explore GATT", systemImage: "link") }
                    .foregroundStyle(Theme.accent)
            }
        }.listRowBackground(Theme.card)
    }

    private func serviceBlock(_ s: BLEScanner.GATTService) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(s.name).font(.callout.weight(.semibold)).foregroundStyle(Theme.accent)
            Text(s.uuid).font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.dim)
            ForEach(s.chars) { c in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(c.name).font(.caption).foregroundStyle(Theme.fg)
                        Spacer()
                        Text(c.props.joined(separator: " · ")).font(.system(size: 9, design: .monospaced)).foregroundStyle(Theme.dim)
                    }
                    if let t = c.valueText { Text("“\(t)”").font(.caption2).foregroundStyle(Theme.accent) }
                    if let h = c.valueHex { Text(h).font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.dim).lineLimit(2) }
                }.padding(.leading, 10)
            }
        }.listRowBackground(Theme.card)
    }

    private func row(_ k: String, _ v: String, mono: Bool = false) -> some View {
        HStack(alignment: .top) {
            Text(k).font(.caption).foregroundStyle(Theme.dim).frame(width: 96, alignment: .leading)
            Text(v).font(mono ? .system(.caption2, design: .monospaced) : .caption).foregroundStyle(Theme.fg)
                .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
        }.listRowBackground(Theme.card)
    }
}
