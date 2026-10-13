import SwiftUI
import ReconCore

enum PortPreset: String, CaseIterable, Identifiable {
    case top20 = "Top 20", top100 = "Top 100", wellKnown = "1–1024", full = "All 65535", custom = "Custom"
    var id: String { rawValue }
    var spec: String? {
        switch self {
        case .top20: return "top20"
        case .top100: return "top100"
        case .wellKnown: return "1-1024"
        case .full: return "all"
        case .custom: return nil
        }
    }
}

@MainActor
final class ScanViewModel: ObservableObject {
    // inputs
    @Published var target = ""
    @Published var preset: PortPreset = .top100
    @Published var customPorts = "22,80,443,8080"
    @Published var grabBanners = true
    @Published var includeUDP = false
    @Published var skipDiscovery = false

    // state
    @Published var running = false
    @Published var done = 0
    @Published var total = 0
    @Published var liveOpen: [PortResult] = []
    @Published var upHosts: [String: String] = [:]
    @Published var results: [HostResult] = []
    @Published var error: String?
    @Published var startedAt: Date?
    private var task: Task<Void, Never>?

    var progress: Double { total == 0 ? 0 : Double(done) / Double(total) }

    func start() {
        error = nil
        results = []
        liveOpen = []
        upHosts = [:]
        done = 0
        total = 0
        do {
            let targets = try TargetParser.expand(target)
            let ports = try PortSpec.parse(preset.spec ?? customPorts)
            var cfg = ScanConfig(targets: targets, ports: ports)
            cfg.grabBanners = grabBanners
            cfg.includeUDP = includeUDP
            cfg.skipDiscovery = skipDiscovery
            cfg.timeout = targets.count > 1 ? 1.0 : 1.5
            running = true
            startedAt = Date()
            task = Task {
                for await ev in PortScanner().scan(cfg) {
                    switch ev {
                    case .started(let t, _): total = t
                    case .hostUp(let h, let why): upHosts[h] = why
                    case .port(let p): liveOpen.append(p)
                    case .progress(let d, let t): done = d; total = t
                    case .finished(let r): results = r; done = total
                    }
                }
                running = false
            }
        } catch {
            self.error = error.localizedDescription
        }
    }

    func stop() {
        task?.cancel()
        task = nil
        running = false
    }
}

struct ScannerView: View {
    enum Mode: String, CaseIterable, Identifiable { case ports = "Port Scan", lan = "LAN Discovery", bonjour = "Bonjour"
        var id: String { rawValue } }

    @StateObject private var scan = ScanViewModel()
    @State private var mode: Mode = .ports

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    Picker("Mode", selection: $mode) {
                        ForEach(Mode.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)

                    switch mode {
                    case .ports: PortScanPanel(scan: scan)
                    case .lan: LANDiscoveryPanel { ip in scan.target = ip; mode = .ports }
                    case .bonjour: BonjourPanel()
                    }
                }
                .padding(16)
            }
            .scrollDismissesKeyboard(.interactively)
            .screenBackground()
            .navigationTitle("Scanner")
        }
    }
}

// MARK: - Port scan

private struct PortScanPanel: View {
    @ObservedObject var scan: ScanViewModel
    @EnvironmentObject private var store: SessionStore
    @State private var saved = false

    var body: some View {
        VStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 10) {
                Text("TARGET").font(.caption2.weight(.bold)).foregroundStyle(Theme.dim)
                TerminalField(placeholder: "host, IP, 10.0.0.0/24, 10.0.0.5-20", text: $scan.target)
                HStack {
                    Button("My network") {
                        if let p = LocalNetwork.primarySubnet() { scan.target = p.subnet.cidr }
                    }.buttonStyle(.bordered).font(.caption)
                    Button("Gateway") {
                        if let p = LocalNetwork.primarySubnet() { scan.target = LocalNetwork.likelyGateway(p.subnet) }
                    }.buttonStyle(.bordered).font(.caption)
                    Button("Localhost") { scan.target = "127.0.0.1" }.buttonStyle(.bordered).font(.caption)
                }

                Text("PORTS").font(.caption2.weight(.bold)).foregroundStyle(Theme.dim).padding(.top, 4)
                Picker("Ports", selection: $scan.preset) {
                    ForEach(PortPreset.allCases) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.menu)
                if scan.preset == .custom {
                    TerminalField(placeholder: "22,80,443,8000-8100", text: $scan.customPorts)
                }
                Toggle("Grab banners & identify versions", isOn: $scan.grabBanners)
                Toggle("Add UDP probes (DNS, NTP, SNMP, SSDP, mDNS, NBNS)", isOn: $scan.includeUDP)
                Toggle("Skip host discovery (-Pn)", isOn: $scan.skipDiscovery)

                Label("TCP connect scan. Only scan hosts you are authorised to test.", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(Severity.medium.color)

                HStack {
                    Button {
                        saved = false
                        scan.start()
                    } label: {
                        HStack { if scan.running { ProgressView().tint(.black) }; Text(scan.running ? "Scanning…" : "Start scan") }
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(scan.running || scan.target.trimmingCharacters(in: .whitespaces).isEmpty)
                    if scan.running {
                        Button("Stop") { scan.stop() }.buttonStyle(PrimaryButtonStyle(tint: Severity.high.color)).frame(width: 100)
                    }
                }
            }
            .card()

            if let e = scan.error {
                Label(e, systemImage: "xmark.octagon.fill").font(.callout).foregroundStyle(Severity.critical.color).card()
            }

            if scan.running || scan.total > 0 {
                VStack(alignment: .leading, spacing: 6) {
                    ProgressView(value: scan.progress).tint(Theme.accent)
                    HStack {
                        Text("\(scan.done)/\(scan.total) probes").font(Theme.mono).foregroundStyle(Theme.dim)
                        Spacer()
                        Text("\(scan.liveOpen.count) open").font(Theme.mono).foregroundStyle(Theme.accent)
                        if scan.upHosts.count > 0 { Text("· \(scan.upHosts.count) hosts up").font(Theme.mono).foregroundStyle(Theme.dim) }
                    }
                }.card()
            }

            if scan.running {
                ForEach(groupedLive(), id: \.0) { host, ports in HostCard(host: host, ports: ports, hint: nil, closed: 0, filtered: 0) }
            } else {
                ForEach(scan.results) { h in
                    HostCard(host: h.host, ports: h.openPorts, hint: h.deviceHint, closed: h.closedCount, filtered: h.filteredCount)
                }
                if !scan.results.isEmpty {
                    Button {
                        store.add(scanReport(target: scan.target, hosts: scan.results))
                        saved = true
                    } label: { Label(saved ? "Saved to Reports" : "Save to Reports", systemImage: saved ? "checkmark" : "tray.and.arrow.down") }
                    .buttonStyle(.bordered).disabled(saved)
                }
            }
        }
    }

    private func groupedLive() -> [(String, [PortResult])] {
        Dictionary(grouping: scan.liveOpen, by: \.host).map { ($0.key, $0.value.sorted { $0.port < $1.port }) }.sorted { $0.0 < $1.0 }
    }
}

private struct HostCard: View {
    let host: String
    let ports: [PortResult]
    let hint: String?
    let closed: Int
    let filtered: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(host).font(.system(.headline, design: .monospaced)).foregroundStyle(Theme.accent)
                Spacer()
                Text("\(ports.count) open").font(.caption).foregroundStyle(Theme.dim)
            }
            if let hint = hint { Text(hint).font(.caption).foregroundStyle(Theme.dim) }
            if ports.isEmpty {
                Text("No open ports found.").font(.caption).foregroundStyle(Theme.dim)
            }
            ForEach(ports) { p in
                let risk = p.proto == "tcp" ? ServiceDB.risk(port: p.port) : nil
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline) {
                        Text("\(p.port)/\(p.proto)").font(.system(.subheadline, design: .monospaced).weight(.bold))
                            .foregroundStyle(risk?.severity.color ?? Color.white)
                            .frame(width: 84, alignment: .leading)
                        Text(p.service).font(Theme.mono)
                        if let v = p.version { Text(v).font(Theme.mono).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true) }
                        Spacer()
                        if let r = risk, r.severity >= .medium { SeverityChip(severity: r.severity) }
                    }
                    if p.version == nil, let b = p.banner, !b.isEmpty {
                        Text(b).font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.dim).lineLimit(5)
                    }
                    if let r = risk, r.severity >= .medium {
                        Text(r.why).font(.caption2).foregroundStyle(r.severity.color.opacity(0.9))
                    }
                }
            }
            if closed + filtered > 0 {
                Text("Not shown: \(closed) closed, \(filtered) filtered/no-response")
                    .font(.caption2).foregroundStyle(Theme.dim)
            }
        }
        .card()
    }
}

// MARK: - LAN discovery

@MainActor
private final class LANModel: ObservableObject {
    @Published var running = false
    @Published var hosts: [(ip: String, why: String)] = []
    @Published var subnet: Subnet?
    @Published var error: String?
    private var task: Task<Void, Never>?

    func start() {
        guard let p = LocalNetwork.primarySubnet() else {
            error = "No private IPv4 network found. Connect to Wi-Fi first."
            return
        }
        error = nil
        subnet = p.subnet
        hosts = []
        running = true
        let all = p.subnet.hostAddresses()
        task = Task {
            let found = await HostDiscovery.sweep(all, onUp: { ip, why in
                Task { @MainActor in
                    if !(self.hosts.contains { $0.ip == ip }) { self.hosts.append((ip, why)) }
                }
            })
            hosts = found.map { (ip: $0.0, why: $0.1) }
            running = false
        }
    }

    func stop() { task?.cancel(); running = false }
}

private struct LANDiscoveryPanel: View {
    let onPick: (String) -> Void
    @StateObject private var lan = LANModel()

    var body: some View {
        VStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Finds live hosts on your Wi-Fi subnet using ICMP echo plus TCP probes (an RST also proves a host is up). iOS will ask for Local Network permission the first time.")
                    .font(.caption).foregroundStyle(Theme.dim)
                if let s = lan.subnet { ItemRow(item: ReportItem("Sweeping", "\(s.cidr)  (\(s.usableHosts) addresses)")) }
                HStack {
                    Button { lan.start() } label: {
                        HStack { if lan.running { ProgressView().tint(.black) }; Text(lan.running ? "Discovering…" : "Discover hosts") }
                    }.buttonStyle(PrimaryButtonStyle()).disabled(lan.running)
                    if lan.running { Button("Stop") { lan.stop() }.buttonStyle(PrimaryButtonStyle(tint: Severity.high.color)).frame(width: 100) }
                }
            }.card()

            if let e = lan.error { Label(e, systemImage: "wifi.slash").font(.callout).foregroundStyle(Severity.high.color).card() }

            if !lan.hosts.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Live hosts (\(lan.hosts.count))").font(.headline).foregroundStyle(Theme.accent)
                    ForEach(lan.hosts.sorted { (IPv4.parse($0.ip) ?? 0) < (IPv4.parse($1.ip) ?? 0) }, id: \.ip) { h in
                        Button { onPick(h.ip) } label: {
                            HStack {
                                Text(h.ip).font(.system(.body, design: .monospaced))
                                Spacer()
                                Text(h.why).font(.caption).foregroundStyle(Theme.dim)
                                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(Theme.dim)
                            }
                        }.buttonStyle(.plain)
                        Divider().overlay(Theme.stroke)
                    }
                    Text("Tap a host to port-scan it.").font(.caption2).foregroundStyle(Theme.dim)
                }.card()
            }
        }
    }
}

// MARK: - Bonjour

@MainActor
private final class BonjourModel: ObservableObject {
    @Published var running = false
    @Published var services: [BonjourService] = []
    @Published var done = false

    func browse() {
        running = true
        done = false
        Task {
            services = await Bonjour.browse(duration: 6)
            running = false
            done = true
        }
    }
}

private struct BonjourPanel: View {
    @StateObject private var model = BonjourModel()

    var body: some View {
        VStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Listens for mDNS/Bonjour announcements for ~6 seconds: printers, Apple TVs, HomeKit, SMB shares, SSH hosts, Chromecasts and more.")
                    .font(.caption).foregroundStyle(Theme.dim)
                Button { model.browse() } label: {
                    HStack { if model.running { ProgressView().tint(.black) }; Text(model.running ? "Listening…" : "Browse services") }
                }.buttonStyle(PrimaryButtonStyle()).disabled(model.running)
            }.card()

            if model.done && model.services.isEmpty {
                Text("No services answered. Check Local Network permission in Settings › Privacy.").font(.caption).foregroundStyle(Theme.dim).card()
            }
            if !model.services.isEmpty {
                let groups = Dictionary(grouping: model.services, by: \.friendlyType).sorted { $0.key < $1.key }
                ForEach(groups, id: \.key) { type, list in
                    VStack(alignment: .leading, spacing: 8) {
                        Text("\(type) (\(list.count))").font(.headline).foregroundStyle(Theme.accent)
                        ForEach(list) { s in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(s.name).font(.subheadline.weight(.semibold))
                                if let a = s.addresses.first {
                                    Text("\(a)\(s.port.map { ":\($0)" } ?? "")").font(Theme.mono).foregroundStyle(Theme.dim).textSelection(.enabled)
                                }
                                if !s.txt.isEmpty {
                                    Text(s.txt.sorted { $0.key < $1.key }.prefix(6).map { "\($0.key)=\($0.value)" }.joined(separator: "  "))
                                        .font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.dim).lineLimit(8)
                                }
                            }
                        }
                    }.card()
                }
            }
        }
    }
}
