import SwiftUI
import ReconCore

struct RootView: View {
    @AppStorage("scopeAccepted") private var accepted = false

    var body: some View {
        TabView {
            DashboardView()
                .tabItem { Label("Home", systemImage: "house.fill") }
            ScannerView()
                .tabItem { Label("Scan", systemImage: "dot.radiowaves.left.and.right") }
            FullReconView()
                .tabItem { Label("Recon", systemImage: "scope") }
            ToolsView()
                .tabItem { Label("Tools", systemImage: "wrench.and.screwdriver.fill") }
            ReportsView()
                .tabItem { Label("Reports", systemImage: "tray.full.fill") }
        }
        .fullScreenCover(isPresented: Binding(get: { !accepted }, set: { _ in })) {
            ScopeView { accepted = true }
        }
    }
}

struct ScopeView: View {
    let onAccept: () -> Void
    @State private var checked = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Spacer()
            Image(systemName: "scope").font(.system(size: 52)).foregroundStyle(Theme.accent)
            Text("ReconKit").font(.largeTitle.bold())
            Text("Network reconnaissance & OSINT toolkit for security professionals.")
                .foregroundStyle(Theme.dim)

            VStack(alignment: .leading, spacing: 10) {
                Label("Active tools (port scans, path probes, TLS/CORS tests, ping) send traffic to the target.", systemImage: "antenna.radiowaves.left.and.right")
                Label("Only assess systems you own or have explicit, written permission to test.", systemImage: "checkmark.shield")
                Label("Unauthorised scanning can be illegal and may violate your network's or ISP's terms.", systemImage: "exclamationmark.triangle")
                Label("Passive OSINT tools query public third-party data sources; nothing is sent to the subject.", systemImage: "eye")
            }
            .font(.callout)
            .card()

            Toggle(isOn: $checked) {
                Text("I will only test systems I am authorised to assess.").font(.callout)
            }
            .toggleStyle(CheckToggleStyle())

            Button("Continue", action: onAccept)
                .buttonStyle(PrimaryButtonStyle())
                .disabled(!checked)
                .opacity(checked ? 1 : 0.4)
            Spacer()
        }
        .padding(24)
        .screenBackground()
        .preferredColorScheme(.dark)
        .interactiveDismissDisabled()
    }
}

private struct CheckToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button { configuration.isOn.toggle() } label: {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: configuration.isOn ? "checkmark.square.fill" : "square")
                    .foregroundStyle(configuration.isOn ? Theme.accent : Theme.dim).font(.title3)
                configuration.label.multilineTextAlignment(.leading)
            }
        }
        .buttonStyle(.plain)
    }
}
