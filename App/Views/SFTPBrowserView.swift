import SwiftUI
import UIKit
import ReconCore

/// Remote file browser over SFTP. Pushed from the terminal / host list.
struct SFTPBrowserView: View {
    @EnvironmentObject private var ssh: SSHStore
    @StateObject private var model: SFTPBrowserModel
    @State private var password = ""
    @State private var privateKey = ""
    @State private var passphrase = ""
    @State private var share: ShareItem?

    private let host: SSHHost

    init(host: SSHHost) {
        self.host = host
        _model = StateObject(wrappedValue: SFTPBrowserModel(host: host))
    }

    var body: some View {
        VStack(spacing: 0) {
            statusBar
            if needsSecret {
                connectForm
            } else {
                pathBar
                listing
            }
        }
        .screenBackground()
        .navigationTitle("Files")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { loadSecrets(); if !needsSecret && model.phase == .idle { startConnect() } }
        .onDisappear { model.disconnect() }
        .onChange(of: model.downloaded) { url in if let url { share = ShareItem(url: url) } }
        .sheet(item: $share) { ShareSheet(items: [$0.url]) }
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            Circle().fill(statusColor).frame(width: 9, height: 9)
            Text(statusText).font(.caption).foregroundStyle(Theme.dim)
            Spacer()
            if model.busy { ProgressView().controlSize(.small) }
            Text(host.endpoint).font(.system(.caption2, design: .monospaced)).foregroundStyle(Theme.dim)
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(Theme.card)
    }

    private var pathBar: some View {
        HStack(spacing: 10) {
            Button { model.up() } label: { Image(systemName: "arrow.up.left.circle") }
                .disabled(model.displayPath == "~/")
            Text(model.displayPath).font(.system(.caption, design: .monospaced)).foregroundStyle(Theme.accent)
                .lineLimit(1).truncationMode(.head)
            Spacer()
            Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(Theme.bg)
    }

    private var listing: some View {
        List {
            if let e = model.error {
                Text(e).font(.caption).foregroundStyle(Severity.high.color).listRowBackground(Theme.card)
            }
            ForEach(model.entries) { entry in
                Button { tap(entry) } label: {
                    HStack(spacing: 12) {
                        Image(systemName: entry.icon).foregroundStyle(entry.isDir ? Theme.accent : Theme.dim).frame(width: 22)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.name).foregroundStyle(Theme.fg).lineLimit(1)
                            Text(entry.perms).font(.system(.caption2, design: .monospaced)).foregroundStyle(Theme.dim)
                        }
                        Spacer()
                        Text(entry.sizeText).font(.caption2).foregroundStyle(Theme.dim)
                        if entry.isDir { Image(systemName: "chevron.right").font(.caption2).foregroundStyle(Theme.dim) }
                        else { Image(systemName: "arrow.down.circle").font(.caption).foregroundStyle(Theme.accent) }
                    }
                }
                .buttonStyle(.plain)
                .listRowBackground(Theme.card)
            }
            if model.entries.isEmpty && model.phase == .ready && model.error == nil {
                Text("Empty directory").font(.caption).foregroundStyle(Theme.dim).listRowBackground(Theme.card)
            }
        }
        .scrollContentBackground(.hidden)
    }

    private var connectForm: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Credentials needed").font(.headline).foregroundStyle(Theme.accent)
                Text("Enter the \(host.auth == .password ? "password" : "private key") for \(host.endpoint) to browse files.")
                    .font(.caption).foregroundStyle(Theme.dim)
                if host.auth == .password {
                    TerminalField(placeholder: "password", text: $password, secure: true)
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Private key (OpenSSH)").font(.caption).foregroundStyle(Theme.dim)
                        TextEditor(text: $privateKey)
                            .font(.system(.caption, design: .monospaced)).frame(minHeight: 140)
                            .autocorrectionDisabled().textInputAutocapitalization(.never)
                            .padding(6).background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
                        TerminalField(placeholder: "key passphrase (optional)", text: $passphrase, secure: true)
                    }
                }
                Button("Connect", action: startConnect)
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(host.auth == .password ? password.isEmpty : privateKey.isEmpty)
            }.padding(18)
        }
    }

    // MARK: Logic

    private var needsSecret: Bool {
        guard model.phase == .idle else { return false }
        return host.auth == .password ? password.isEmpty : privateKey.isEmpty
    }

    private var statusColor: Color {
        switch model.phase {
        case .ready: return Severity.low.color
        case .connecting: return Severity.medium.color
        case .failed: return Severity.critical.color
        case .idle: return Theme.dim
        }
    }
    private var statusText: String {
        switch model.phase {
        case .idle: return "Not connected"
        case .connecting: return "Connecting…"
        case .ready: return "Connected"
        case .failed(let m): return m
        }
    }

    private func tap(_ entry: SFTPBrowserModel.Entry) {
        if entry.isDir { model.enter(entry) } else { model.download(entry) }
    }

    private func loadSecrets() {
        password = ssh.password(for: host.id) ?? ""
        privateKey = ssh.privateKey(for: host.id) ?? ""
        passphrase = ssh.passphrase(for: host.id) ?? ""
    }

    private func startConnect() {
        ssh.markUsed(host)
        model.connect(password: password, privateKey: privateKey, passphrase: passphrase)
    }
}

private struct ShareItem: Identifiable { let id = UUID(); let url: URL }

/// Minimal UIActivityViewController wrapper for sharing / saving a downloaded file.
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
