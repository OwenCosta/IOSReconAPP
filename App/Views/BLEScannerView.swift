import SwiftUI
import ReconCore

/// Live BLE scanner UI. Pushed from the dashboard.
struct BLEScannerView: View {
    @StateObject private var scanner = BLEScanner()

    var body: some View {
        VStack(spacing: 0) {
            statusBar
            if scanner.devices.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "dot.radiowaves.left.and.right").font(.system(size: 42)).foregroundStyle(Theme.dim)
                    Text(emptyText).font(.callout).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
                }.padding(40).frame(maxHeight: .infinity)
            } else {
                List {
                    if scanner.cameraCount > 0 {
                        HStack(spacing: 8) {
                            Image(systemName: "video.fill").foregroundStyle(Severity.high.color)
                            Text("\(scanner.cameraCount) possible camera\(scanner.cameraCount == 1 ? "" : "s") beaconing nearby")
                                .font(.caption.weight(.semibold)).foregroundStyle(Theme.fg)
                        }
                        .listRowBackground(Severity.high.color.opacity(0.15))
                    }
                    ForEach(scanner.devices) { d in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: d.categoryIcon)
                                    .foregroundStyle(d.isCamera ? Severity.high.color : (d.connectable ? Theme.accent : Theme.dim))
                                Text(d.name).font(.body.weight(.semibold)).foregroundStyle(Theme.fg).lineLimit(1)
                                Spacer()
                                signal(d.signalBars)
                                Text("\(d.rssi) dBm").font(.system(.caption2, design: .monospaced)).foregroundStyle(Theme.dim)
                            }
                            HStack(spacing: 8) {
                                tag(d.category, d.isCamera ? Severity.high.color : Theme.accent)
                                if let v = d.vendor { tag(v, Theme.dim) }
                                if d.connectable { tag("connectable", Severity.low.color) }
                                if !d.services.isEmpty { tag("\(d.services.count) svc", Theme.dim) }
                            }
                            if let note = d.note {
                                Text(note).font(.caption2).foregroundStyle(Theme.dim).lineLimit(3)
                            }
                            if !d.services.isEmpty {
                                Text(d.services.prefix(4).joined(separator: ", "))
                                    .font(.system(.caption2, design: .monospaced)).foregroundStyle(Theme.dim).lineLimit(2)
                            }
                            Text(d.id.uuidString).font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.dim.opacity(0.7))
                        }
                        .padding(.vertical, 2)
                        .listRowBackground(Theme.card)
                    }
                }
                .scrollContentBackground(.hidden)
            }
        }
        .screenBackground()
        .navigationTitle("Bluetooth (BLE)")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
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
            Text("\(scanner.devices.count) devices").font(.caption).foregroundStyle(Theme.dim)
            if scanner.state == .scanning { ProgressView().controlSize(.small) }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(Theme.card)
    }

    private func signal(_ bars: Int) -> some View {
        HStack(spacing: 1.5) {
            ForEach(1...4, id: \.self) { i in
                RoundedRectangle(cornerRadius: 1)
                    .fill(i <= bars ? Theme.accent : Theme.dim.opacity(0.3))
                    .frame(width: 3, height: CGFloat(4 + i * 3))
            }
        }
    }

    private func tag(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 10, weight: .medium))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }

    private var stateText: String {
        switch scanner.state {
        case .unknown: return "Starting…"
        case .scanning: return "Scanning for BLE devices"
        case .stopped: return "Stopped"
        case .poweredOff: return "Turn on Bluetooth in Control Centre"
        case .unauthorized: return "Allow Bluetooth in Settings › Privacy"
        case .unsupported: return "BLE not available on this device"
        }
    }

    private var emptyText: String {
        switch scanner.state {
        case .scanning, .unknown: return "Listening for nearby Bluetooth Low Energy advertisers…\nWearables, beacons, trackers and smart-home gear will appear here."
        case .poweredOff: return "Bluetooth is off. Turn it on in Control Centre to scan."
        case .unauthorized: return "Bluetooth permission denied. Enable it in Settings › Privacy & Security › Bluetooth."
        case .unsupported: return "This device/build can't scan BLE."
        case .stopped: return "Scan stopped."
        }
    }
}
