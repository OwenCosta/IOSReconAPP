import SwiftUI
import ReconCore

@MainActor
final class DashboardModel: ObservableObject {
    @Published var interfaces: [NetInterface] = []
    @Published var subnet: Subnet?
    @Published var gateway: String?
    @Published var publicIP: IPIntel.Geo?
    @Published var publicError: String?
    @Published var loadingPublic = false

    func refreshLocal() {
        interfaces = LocalNetwork.interfaces().filter { $0.isUp && !$0.address.hasPrefix("fe80") && !$0.name.hasPrefix("lo") && !$0.name.hasPrefix("awdl") && !$0.name.hasPrefix("llw") }
        if let p = LocalNetwork.primarySubnet() {
            subnet = p.subnet
            gateway = LocalNetwork.likelyGateway(p.subnet)
        } else {
            subnet = nil
            gateway = nil
        }
    }

    func refreshPublic() {
        loadingPublic = true
        publicError = nil
        Task {
            do { publicIP = try await IPIntel.myIP() } catch { publicError = error.localizedDescription }
            loadingPublic = false
        }
    }
}

struct DashboardView: View {
    @EnvironmentObject private var store: SessionStore
    @EnvironmentObject private var notes: NotesStore
    @StateObject private var model = DashboardModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    networkCard
                    copilotCard
                    terminalCard
                    cameraDiscoveryCard
                    bluetoothCard
                    flagCard
                    publicCard
                    capabilityCard
                    if let latest = store.reports.first {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Latest report").font(.headline).foregroundStyle(Theme.accent)
                            NavigationLink { ReportDetailView(report: latest) } label: { ReportRow(report: latest) }
                                .buttonStyle(.plain)
                        }.card()
                    }
                }
                .padding(16)
            }
            .screenBackground()
            .navigationTitle("NetTactix")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    NavigationLink { NotesView() } label: { Image(systemName: "flag.fill") }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink { TerminalHomeView() } label: { Image(systemName: "terminal") }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink { ReportsScreen() } label: { Image(systemName: "tray.full") }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink { SettingsView() } label: { Image(systemName: "gearshape") }
                }
            }
            .onAppear {
                model.refreshLocal()
                if model.publicIP == nil && !model.loadingPublic { model.refreshPublic() }
            }
            .refreshable { model.refreshLocal(); model.refreshPublic() }
        }
    }

    private var networkCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("Local network", systemImage: "wifi").font(.headline).foregroundStyle(Theme.accent)
                Spacer()
                Button { model.refreshLocal() } label: { Image(systemName: "arrow.clockwise") }
            }
            if let s = model.subnet {
                ItemRow(item: ReportItem("Subnet", s.cidr))
                if let g = model.gateway { ItemRow(item: ReportItem("Gateway (guess)", g)) }
                ItemRow(item: ReportItem("Hosts", "\(s.usableHosts) addresses"))
            } else {
                Text("Not on a private Wi-Fi network. Connect to Wi-Fi to scan your LAN.")
                    .font(.caption).foregroundStyle(Theme.dim)
            }
            ForEach(model.interfaces) { i in
                ItemRow(item: ReportItem("\(i.name) · \(i.kind)", i.address))
            }
        }
        .card()
    }

    private var publicCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("Public identity", systemImage: "globe").font(.headline).foregroundStyle(Theme.accent)
                Spacer()
                if model.loadingPublic { ProgressView() }
                else { Button { model.refreshPublic() } label: { Image(systemName: "arrow.clockwise") } }
            }
            if let g = model.publicIP {
                ItemRow(item: ReportItem("IP", g.ip))
                ItemRow(item: ReportItem("Location", [g.city, g.region, g.country].compactMap { $0 }.joined(separator: ", ")))
                if let a = g.asn { ItemRow(item: ReportItem("ASN", a)) }
                if let o = g.org ?? g.isp { ItemRow(item: ReportItem("Network", o)) }
            } else if let e = model.publicError {
                Text(e).font(.caption).foregroundStyle(Severity.high.color)
            }
        }
        .card()
    }

    private var terminalCard: some View {
        NavigationLink { TerminalHomeView() } label: {
            HStack(spacing: 12) {
                Image(systemName: "terminal.fill").font(.title3).foregroundStyle(Theme.accent).frame(width: 26)
                VStack(alignment: .leading, spacing: 2) {
                    Text("SSH Terminal").font(.headline).foregroundStyle(Theme.accent)
                    Text("Connect to your servers and run commands live, no laptop needed")
                        .font(.caption).foregroundStyle(Theme.dim)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(Theme.dim)
            }
            .card()
        }
        .buttonStyle(.plain)
    }

    private var copilotCard: some View {
        NavigationLink { AssistantHomeView() } label: {
            HStack(spacing: 12) {
                Image(systemName: "sparkles").font(.title3).foregroundStyle(Theme.accent).frame(width: 26)
                VStack(alignment: .leading, spacing: 2) {
                    Text("AI Assistant").font(.headline).foregroundStyle(Theme.accent)
                    Text("Chat with a local or API AI for recon, CTF & app help, saved on-device")
                        .font(.caption).foregroundStyle(Theme.dim)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(Theme.dim)
            }
            .card()
        }
        .buttonStyle(.plain)
    }

    private var cameraDiscoveryCard: some View {
        NavigationLink { ToolRunnerView(spec: ToolCatalog.all.first { $0.id == "camera-auto" } ?? ToolCatalog.all[0]) } label: {
            HStack(spacing: 12) {
                Image(systemName: "video.badge.waveform").font(.title3).foregroundStyle(Severity.high.color).frame(width: 26)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Camera Auto-Discovery").font(.headline).foregroundStyle(Theme.accent)
                    Text("Find cameras on this Wi-Fi automatically: WS-Discovery + mDNS")
                        .font(.caption).foregroundStyle(Theme.dim)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(Theme.dim)
            }
            .card()
        }
        .buttonStyle(.plain)
    }

    private var bluetoothCard: some View {
        NavigationLink { BLEScannerView() } label: {
            HStack(spacing: 12) {
                Image(systemName: "dot.radiowaves.left.and.right").font(.title3).foregroundStyle(Theme.accent).frame(width: 26)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Bluetooth Scanner").font(.headline).foregroundStyle(Theme.accent)
                    Text("Discover nearby BLE devices: name, vendor, services, signal")
                        .font(.caption).foregroundStyle(Theme.dim)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(Theme.dim)
            }
            .card()
        }
        .buttonStyle(.plain)
    }

    private var flagCard: some View {
        NavigationLink { NotesView() } label: {
            HStack(spacing: 12) {
                Image(systemName: "flag.checkered").font(.title3).foregroundStyle(Theme.accent).frame(width: 26)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Flag Tracker").font(.headline).foregroundStyle(Theme.accent)
                    Text(notes.notes.isEmpty ? "Track challenges & flags for the competition"
                                             : "\(notes.solvedCount) solved · \(notes.notes.count) tracked")
                        .font(.caption).foregroundStyle(Theme.dim)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(Theme.dim)
            }
            .card()
        }
        .buttonStyle(.plain)
    }

    private var capabilityCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("What this app can do").font(.headline).foregroundStyle(Theme.accent)
            Group {
                Text("• TCP connect scanner with banner grabbing & service ID, UDP probes")
                Text("• LAN discovery (ICMP + TCP), Bonjour/mDNS browsing")
                Text("• Full automated recon: DNS, email posture, RDAP, CT logs, web, TLS, ports")
                Text("• OSINT: usernames, emails, GitHub, Wayback, Shodan InternetDB")
                Text("• Findings are risk-ranked and exportable as Markdown / JSON")
            }
            .font(.caption).foregroundStyle(Theme.dim)
            Text("iOS blocks raw sockets, so SYN scans, OS fingerprinting and packet crafting are not possible on-device.")
                .font(.caption2).foregroundStyle(Theme.dim.opacity(0.8)).padding(.top, 4)
        }
        .card()
    }
}
