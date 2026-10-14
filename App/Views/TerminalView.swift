import SwiftUI

/// Saved SSH hosts + entry to the live terminal. Pushed from the dashboard stack.
struct TerminalHomeView: View {
    @EnvironmentObject private var ssh: SSHStore
    @State private var editing: SSHHost?
    @State private var creating = false

    var body: some View {
        Group {
            if ssh.hosts.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "terminal").font(.system(size: 44)).foregroundStyle(Theme.dim)
                    Text("No saved servers").font(.headline)
                    Text("Add an SSH server to open a live terminal on your phone — run commands, triage boxes and pivot without a laptop.")
                        .font(.caption).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
                    Button { creating = true } label: { Label("Add server", systemImage: "plus") }
                        .buttonStyle(PrimaryButtonStyle()).frame(maxWidth: 240)
                }.padding(32)
            } else {
                List {
                    Section {
                        ForEach(ssh.hosts) { host in
                            NavigationLink { SSHSessionView(host: host) } label: { hostRow(host) }
                                .listRowBackground(Theme.card)
                                .swipeActions(edge: .trailing) {
                                    Button(role: .destructive) { ssh.delete(host) } label: { Label("Delete", systemImage: "trash") }
                                    Button { editing = host } label: { Label("Edit", systemImage: "pencil") }.tint(Theme.accent)
                                }
                        }
                    } header: {
                        Text("Servers").foregroundStyle(Theme.accent)
                    } footer: {
                        Text("Credentials are stored only in this device's Keychain. Host keys are accepted on first use (trust-on-first-use).")
                            .font(.caption2).foregroundStyle(Theme.dim)
                    }
                }
                .scrollContentBackground(.hidden)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .screenBackground()
        .navigationTitle("Terminal")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { creating = true } label: { Image(systemName: "plus") }
            }
        }
        .sheet(isPresented: $creating) { SSHHostEditor(host: SSHHost()) }
        .sheet(item: $editing) { h in SSHHostEditor(host: h) }
    }

    private func hostRow(_ host: SSHHost) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "server.rack").foregroundStyle(Theme.accent).frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(host.displayName).font(.body.weight(.semibold)).foregroundStyle(Theme.fg)
                Text(host.endpoint).font(.caption).foregroundStyle(Theme.dim)
            }
            Spacer()
            Text(host.auth.label).font(.caption2).foregroundStyle(Theme.dim)
        }
    }
}

/// Add / edit an SSH host and its secret.
struct SSHHostEditor: View {
    @EnvironmentObject private var ssh: SSHStore
    @Environment(\.dismiss) private var dismiss
    @State var host: SSHHost
    @State private var password = ""
    @State private var privateKey = ""
    @State private var passphrase = ""
    @State private var portText = "22"

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    labeled("Name (optional)") { TextField("my-box", text: $host.name).textInputAutocapitalization(.never) }
                    labeled("Host") { TextField("10.10.10.5 or box.htb", text: $host.host).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL) }
                    labeled("Port") { TextField("22", text: $portText).keyboardType(.numberPad) }
                    labeled("Username") { TextField("root", text: $host.username).textInputAutocapitalization(.never).autocorrectionDisabled() }
                }
                Section("Authentication") {
                    Picker("Method", selection: $host.auth) {
                        ForEach(SSHHost.Auth.allCases) { Text($0.label).tag($0) }
                    }.pickerStyle(.segmented)

                    if host.auth == .password {
                        SecureField("Password", text: $password)
                        Toggle("Save password in Keychain", isOn: $host.savePassword)
                    } else {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Private key (OpenSSH format)").font(.caption).foregroundStyle(Theme.dim)
                            TextEditor(text: $privateKey)
                                .font(.system(.caption, design: .monospaced))
                                .frame(minHeight: 120)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                        }
                        SecureField("Key passphrase (if encrypted)", text: $passphrase)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(host.host.isEmpty ? "New server" : host.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("Save") { save() }.disabled(!canSave) }
            }
            .onAppear(perform: load)
        }
    }

    private var canSave: Bool {
        var h = host
        h.port = Int(portText) ?? 0
        return h.isValid
    }

    private func load() {
        portText = String(host.port)
        password = ssh.password(for: host.id) ?? ""
        privateKey = ssh.privateKey(for: host.id) ?? ""
        passphrase = ssh.passphrase(for: host.id) ?? ""
    }

    private func save() {
        host.port = Int(portText) ?? 22
        ssh.upsert(host)
        if host.auth == .password {
            ssh.setPassword(host.savePassword ? password : nil, for: host.id)
            ssh.setPrivateKey(nil, for: host.id)
        } else {
            ssh.setPrivateKey(privateKey, for: host.id)
            ssh.setPassphrase(passphrase.isEmpty ? nil : passphrase, for: host.id)
        }
        dismiss()
    }

    private func labeled<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        HStack {
            Text(title).foregroundStyle(Theme.dim).font(.caption).frame(width: 120, alignment: .leading)
            content()
        }
    }
}

/// The live terminal screen.
struct SSHSessionView: View {
    @EnvironmentObject private var ssh: SSHStore
    @StateObject private var model: SSHTerminalModel
    @State private var input = ""
    @State private var password = ""
    @State private var privateKey = ""
    @State private var passphrase = ""
    @FocusState private var inputFocused: Bool

    private let host: SSHHost

    init(host: SSHHost) {
        self.host = host
        _model = StateObject(wrappedValue: SSHTerminalModel(host: host))
    }

    var body: some View {
        VStack(spacing: 0) {
            statusBar
            if needsSecret {
                connectForm
            } else {
                terminal
                controlBar
                inputBar
            }
        }
        .screenBackground()
        .navigationTitle(host.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Menu {
                    Button { model.clearScreen() } label: { Label("Clear screen", systemImage: "clear") }
                    if model.isLive || model.phase == .connecting {
                        Button(role: .destructive) { model.disconnect() } label: { Label("Disconnect", systemImage: "bolt.horizontal") }
                    }
                } label: { Image(systemName: "ellipsis.circle") }
            }
        }
        .onAppear { loadSecrets(); if !needsSecret && model.phase == .idle { startConnect() } }
        .onDisappear { model.disconnect() }
    }

    // MARK: Sub-views

    private var statusBar: some View {
        HStack(spacing: 8) {
            Circle().fill(statusColor).frame(width: 9, height: 9)
            Text(statusText).font(.caption).foregroundStyle(Theme.dim)
            Spacer()
            Text(host.endpoint).font(.system(.caption2, design: .monospaced)).foregroundStyle(Theme.dim)
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(Theme.card)
    }

    private var terminal: some View {
        ScrollViewReader { proxy in
            ScrollView {
                Text(model.screen.isEmpty ? " " : model.screen)
                    .font(.system(size: 12.5, design: .monospaced))
                    .foregroundStyle(Theme.fg)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .id("bottom-anchor-content")
                Color.clear.frame(height: 1).id("bottom")
            }
            .background(Color.black.opacity(0.4))
            .onChange(of: model.screen) { _ in withAnimation(.linear(duration: 0.1)) { proxy.scrollTo("bottom", anchor: .bottom) } }
        }
    }

    private var controlBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                keyButton("Ctrl-C") { model.sendControl(0x03) }
                keyButton("Ctrl-D") { model.sendControl(0x04) }
                keyButton("Ctrl-Z") { model.sendControl(0x1A)}
                keyButton("Tab") { model.send("\t") }
                keyButton("Esc") { model.sendControl(0x1B) }
                keyButton("↑") { model.send("\u{1B}[A") }
                keyButton("↓") { model.send("\u{1B}[B") }
                keyButton("clear") { model.clearScreen() }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
        }
        .background(Theme.card)
        .disabled(!model.isLive)
        .opacity(model.isLive ? 1 : 0.4)
    }

    private var inputBar: some View {
        HStack(spacing: 8) {
            TextField("command", text: $input)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.system(.body, design: .monospaced))
                .focused($inputFocused)
                .onSubmit(submit)
                .padding(10)
                .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
            Button(action: submit) { Image(systemName: "return").font(.body.weight(.semibold)) }
                .buttonStyle(.plain).foregroundStyle(Theme.accent)
                .frame(width: 40, height: 40)
                .background(Theme.raised, in: RoundedRectangle(cornerRadius: 10))
        }
        .padding(10)
        .background(Theme.card)
        .disabled(!model.isLive)
        .opacity(model.isLive ? 1 : 0.4)
    }

    private var connectForm: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Credentials needed").font(.headline).foregroundStyle(Theme.accent)
                Text("Enter the \(host.auth == .password ? "password" : "private key") for \(host.endpoint) to connect.")
                    .font(.caption).foregroundStyle(Theme.dim)
                if host.auth == .password {
                    TerminalField(placeholder: "password", text: $password, secure: true)
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Private key (OpenSSH)").font(.caption).foregroundStyle(Theme.dim)
                        TextEditor(text: $privateKey)
                            .font(.system(.caption, design: .monospaced))
                            .frame(minHeight: 140)
                            .autocorrectionDisabled().textInputAutocapitalization(.never)
                            .padding(6)
                            .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
                        TerminalField(placeholder: "key passphrase (optional)", text: $passphrase, secure: true)
                    }
                }
                Button("Connect", action: startConnect)
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(host.auth == .password ? password.isEmpty : privateKey.isEmpty)
            }.padding(18)
        }
    }

    private func keyButton(_ label: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(label).font(.system(size: 12, weight: .medium, design: .monospaced))
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(Theme.raised, in: RoundedRectangle(cornerRadius: 8))
                .foregroundStyle(Theme.fg)
        }.buttonStyle(.plain)
    }

    // MARK: Logic

    private var needsSecret: Bool {
        guard model.phase == .idle else { return false }
        return host.auth == .password ? password.isEmpty : privateKey.isEmpty
    }

    private var statusColor: Color {
        switch model.phase {
        case .connected: return Severity.low.color
        case .connecting: return Severity.medium.color
        case .failed: return Severity.critical.color
        case .closed, .idle: return Theme.dim
        }
    }

    private var statusText: String {
        switch model.phase {
        case .idle: return "Not connected"
        case .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .closed: return "Disconnected"
        case .failed(let m): return m
        }
    }

    private func loadSecrets() {
        password = ssh.password(for: host.id) ?? ""
        privateKey = ssh.privateKey(for: host.id) ?? ""
        passphrase = ssh.passphrase(for: host.id) ?? ""
    }

    private func startConnect() {
        ssh.markUsed(host)
        model.connect(password: password, privateKey: privateKey, passphrase: passphrase)
        inputFocused = true
    }

    private func submit() {
        model.sendLine(input)
        input = ""
    }
}
