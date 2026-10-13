import SwiftUI
import ReconCore

struct ReportsView: View {
    @EnvironmentObject private var store: SessionStore

    var body: some View {
        NavigationStack {
            Group {
                if store.reports.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "tray").font(.system(size: 44)).foregroundStyle(Theme.dim)
                        Text("No reports yet").font(.headline)
                        Text("Full Recon runs are saved automatically. Tool and scan results can be saved manually.")
                            .font(.caption).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
                    }.padding(40)
                } else {
                    List {
                        ForEach(store.reports) { r in
                            NavigationLink { ReportDetailView(report: r) } label: { ReportRow(report: r) }
                                .listRowBackground(Theme.card)
                        }
                        .onDelete { store.delete(at: $0) }
                    }
                    .scrollContentBackground(.hidden)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .screenBackground()
            .navigationTitle("Reports")
            .toolbar { if !store.reports.isEmpty { ToolbarItem(placement: .topBarTrailing) { EditButton() } } }
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject private var store: SessionStore
    @State private var shodan = KeychainSecrets.get("shodan") ?? ""
    @State private var virustotal = KeychainSecrets.get("virustotal") ?? ""
    @State private var hibp = KeychainSecrets.get("hibp") ?? ""
    @State private var github = KeychainSecrets.get("github") ?? ""
    @State private var confirmClear = false

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                VStack(alignment: .leading, spacing: 12) {
                    Text("API keys").font(.headline).foregroundStyle(Theme.accent)
                    Text("Optional. Keys are stored in the iOS Keychain on this device only and are sent solely to the matching service.")
                        .font(.caption).foregroundStyle(Theme.dim)
                    keyField("Shodan", "shodan", $shodan)
                    keyField("VirusTotal", "virustotal", $virustotal)
                    keyField("Have I Been Pwned", "hibp", $hibp)
                    keyField("GitHub token (raises rate limit)", "github", $github)
                }.card()

                VStack(alignment: .leading, spacing: 8) {
                    Text("Data").font(.headline).foregroundStyle(Theme.accent)
                    Button(role: .destructive) { confirmClear = true } label: { Label("Delete all saved reports (\(store.reports.count))", systemImage: "trash") }
                        .disabled(store.reports.isEmpty)
                }.card()

                VStack(alignment: .leading, spacing: 8) {
                    Text("Platform limits").font(.headline).foregroundStyle(Theme.accent)
                    Group {
                        Text("• iOS forbids raw sockets: scans are TCP connect() scans, not SYN scans; there is no OS fingerprinting or packet crafting.")
                        Text("• Local-network scanning needs the Local Network permission (Settings › Privacy & Security).")
                        Text("• Background execution is limited: keep the app in the foreground during long scans.")
                        Text("• Scanning over cellular goes through the carrier NAT and is usually heavily filtered.")
                    }.font(.caption).foregroundStyle(Theme.dim)
                }.card()
            }
            .padding(16)
        }
        .screenBackground()
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Delete all reports?", isPresented: $confirmClear, titleVisibility: .visible) {
            Button("Delete", role: .destructive) { store.clear() }
        }
    }

    private func keyField(_ title: String, _ name: String, _ binding: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(Theme.dim)
            TerminalField(placeholder: "not set", text: binding, secure: true)
                .onChange(of: binding.wrappedValue) { KeychainSecrets.set($0, for: name) }
        }
    }
}
