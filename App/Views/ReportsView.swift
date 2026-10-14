import SwiftUI
import ReconCore

/// Pushed from the dashboard's navigation stack, so it does not wrap its own NavigationStack.
/// Reports are organised into folders (projects).
struct ReportsScreen: View {
    @EnvironmentObject private var store: SessionStore
    @State private var query = ""
    @State private var renaming: String?
    @State private var renameText = ""
    @State private var confirmDelete: String?
    @State private var creatingFolder = false
    @State private var newFolderName = ""

    private var folders: [String] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return store.folders }
        return store.folders.filter { f in
            f.lowercased().contains(q) || store.reports(in: f).contains { $0.target.lowercased().contains(q) || $0.kind.lowercased().contains(q) }
        }
    }

    private var isEmpty: Bool { store.reports.isEmpty && store.createdFolders.isEmpty }

    var body: some View {
        Group {
            if isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "folder").font(.system(size: 44)).foregroundStyle(Theme.dim)
                    Text("No reports yet").font(.headline)
                    Text("Full Recon runs save automatically into a folder named after the target. Tool and scan results save into a matching folder too.")
                        .font(.caption).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
                    Button { newFolderName = ""; creatingFolder = true } label: {
                        Label("New folder", systemImage: "folder.badge.plus")
                    }.padding(.top, 6)
                }.padding(40)
            } else {
                List {
                    ForEach(folders, id: \.self) { folder in
                        let items = store.reports(in: folder)
                        let collapsed = store.isCollapsed(folder)
                        Section {
                            if !collapsed {
                                ForEach(items) { r in
                                    NavigationLink { ReportDetailView(report: r) } label: { ReportRow(report: r) }
                                        .listRowBackground(Theme.card)
                                        .swipeActions(edge: .trailing) {
                                            Button(role: .destructive) { store.delete(r) } label: { Label("Delete", systemImage: "trash") }
                                        }
                                        .contextMenu { moveMenu(for: r) }
                                }
                                if items.isEmpty {
                                    Text("Empty — move reports here, or results will land here when you name a run “\(folder)”.")
                                        .font(.caption).foregroundStyle(Theme.dim)
                                        .listRowBackground(Theme.card)
                                }
                            }
                        } header: {
                            HStack(spacing: 8) {
                                Button { withAnimation { store.toggleCollapse(folder) } } label: {
                                    Image(systemName: collapsed ? "chevron.right" : "chevron.down")
                                        .font(.caption.weight(.bold)).foregroundStyle(Theme.dim)
                                        .frame(width: 16)
                                    Image(systemName: folder == SessionStore.unsorted ? "tray" : "folder.fill").foregroundStyle(Theme.accent)
                                    Text(folder).foregroundStyle(Theme.accent)
                                }.buttonStyle(.plain)
                                Spacer()
                                Text("\(items.count)").foregroundStyle(Theme.dim)
                                Menu {
                                    if folder != SessionStore.unsorted {
                                        Button { renaming = folder; renameText = folder } label: { Label("Rename folder", systemImage: "pencil") }
                                    }
                                    Button { withAnimation { store.toggleCollapse(folder) } } label: {
                                        Label(collapsed ? "Expand" : "Collapse", systemImage: collapsed ? "chevron.down" : "chevron.up")
                                    }
                                    Button(role: .destructive) { confirmDelete = folder } label: { Label("Delete folder", systemImage: "trash") }
                                } label: { Image(systemName: "ellipsis.circle").foregroundStyle(Theme.dim) }
                            }
                        }
                    }
                }
                .scrollContentBackground(.hidden)
                .searchable(text: $query, prompt: "Search reports")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .screenBackground()
        .navigationTitle("Reports")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { newFolderName = ""; creatingFolder = true } label: { Image(systemName: "folder.badge.plus") }
            }
        }
        .alert("New folder", isPresented: $creatingFolder) {
            TextField("Folder name", text: $newFolderName)
            Button("Cancel", role: .cancel) { }
            Button("Create") { store.createFolder(newFolderName) }
        }
        .alert("Rename folder", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField("Folder name", text: $renameText)
            Button("Cancel", role: .cancel) { renaming = nil }
            Button("Rename") { if let old = renaming { store.renameFolder(old, to: renameText) }; renaming = nil }
        }
        .confirmationDialog("Delete this folder and all its reports?", isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }), titleVisibility: .visible) {
            Button("Delete", role: .destructive) { if let f = confirmDelete { store.deleteFolder(f) }; confirmDelete = nil }
        }
    }

    @ViewBuilder private func moveMenu(for r: ReconReport) -> some View {
        Menu {
            Button { store.move(r, to: nil) } label: { Label("Unsorted", systemImage: "tray") }
            ForEach(store.folders.filter { $0 != SessionStore.unsorted && $0 != store.folder(of: r) }, id: \.self) { f in
                Button { store.move(r, to: f) } label: { Label(f, systemImage: "folder") }
            }
            // Only offered when it'd actually create something new — otherwise this is always
            // listed regardless of context, making it easy to spawn a one-off folder per report.
            if !r.target.isEmpty, !store.folders.contains(r.target), store.folder(of: r) != r.target {
                Button { store.move(r, to: r.target) } label: { Label("New: \(r.target)", systemImage: "folder.badge.plus") }
            }
        } label: { Label("Move to folder", systemImage: "folder") }
    }
}

struct SettingsView: View {
    @EnvironmentObject private var store: SessionStore
    @EnvironmentObject private var entitlements: Entitlements
    @State private var shodan = KeychainSecrets.get("shodan") ?? ""
    @State private var virustotal = KeychainSecrets.get("virustotal") ?? ""
    @State private var hibp = KeychainSecrets.get("hibp") ?? ""
    @State private var github = KeychainSecrets.get("github") ?? ""
    @State private var confirmClear = false
    @State private var showPaywall = false
    @State private var reviewingScope = false

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Button { showPaywall = true } label: {
                    HStack(spacing: 12) {
                        Image(systemName: entitlements.isPro ? "crown.fill" : "crown").font(.title3).foregroundStyle(Theme.accent).frame(width: 26)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entitlements.isPro ? "NetTactix Pro — active" : "Upgrade to NetTactix Pro").font(.headline).foregroundStyle(Theme.accent)
                            Text(entitlements.isPro ? "Thanks for supporting OathSec" : "See Free vs Pro (\(Entitlements.proPriceText))").font(.caption).foregroundStyle(Theme.dim)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").font(.caption).foregroundStyle(Theme.dim)
                    }.card()
                }.buttonStyle(.plain)
                VStack(alignment: .leading, spacing: 12) {
                    Text("API keys").font(.headline).foregroundStyle(Theme.accent)
                    Text("Optional. Keys are stored in the iOS Keychain on this device only and are sent solely to the matching service.")
                        .font(.caption).foregroundStyle(Theme.dim)
                    APIKeyField(title: "Shodan", name: "shodan", value: $shodan)
                    APIKeyField(title: "VirusTotal", name: "virustotal", value: $virustotal)
                    APIKeyField(title: "Have I Been Pwned", name: "hibp", value: $hibp)
                    APIKeyField(title: "GitHub token (raises rate limit)", name: "github", value: $github)
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

                VStack(alignment: .leading, spacing: 8) {
                    Text("About").font(.headline).foregroundStyle(Theme.accent)
                    Button { reviewingScope = true } label: {
                        Label("Review authorised-use agreement", systemImage: "checkmark.shield")
                    }
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
        .sheet(isPresented: $showPaywall) { PaywallView() }
        .sheet(isPresented: $reviewingScope) { ScopeView(onAccept: {}, reviewOnly: true) }
    }
}

/// One API-key field: shows whether it's currently set, lets you reveal/hide the value (these
/// aren't secrets you need obscured while typing, just awkward to verify when masked), and
/// flashes a brief confirmation when a change is actually saved to the Keychain.
private struct APIKeyField: View {
    let title: String
    let name: String
    @Binding var value: String
    @State private var revealed = false
    @State private var justSaved = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(title).font(.caption).foregroundStyle(Theme.dim)
                Text(value.isEmpty ? "Not set" : "Set")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 1)
                    .background((value.isEmpty ? Theme.dim : Theme.accent).opacity(0.15), in: Capsule())
                    .foregroundStyle(value.isEmpty ? Theme.dim : Theme.accent)
                if justSaved {
                    Label("Saved", systemImage: "checkmark").font(.caption2).foregroundStyle(Theme.accent)
                        .transition(.opacity)
                }
                Spacer()
            }
            HStack(spacing: 8) {
                TerminalField(placeholder: "not set", text: $value, secure: !revealed)
                Button { revealed.toggle() } label: {
                    Image(systemName: revealed ? "eye.slash" : "eye").foregroundStyle(Theme.dim)
                }
            }
        }
        .onChange(of: value) { newValue in
            KeychainSecrets.set(newValue, for: name)
            withAnimation { justSaved = true }
            Task {
                try? await Task.sleep(nanoseconds: 1_200_000_000)
                withAnimation { justSaved = false }
            }
        }
    }
}
