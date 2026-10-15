import SwiftUI
import ReconCore

/// Conversation list + entry to the AI assistant. Pushed from the dashboard.
struct AssistantHomeView: View {
    @EnvironmentObject private var ai: AIStore
    @EnvironmentObject private var localModel: LocalModelStore
    @State private var addingProvider = false
    @State private var managingProviders = false
    @State private var startedChat: AIConversation?
    @State private var showChat = false

    var body: some View {
        Group {
            if ai.providers.isEmpty {
                emptyProviders
            } else {
                List {
                    Section {
                        Toggle(isOn: $ai.toolsAllowed) {
                            Label("Allow Copilot to use tools", systemImage: "wrench.and.screwdriver")
                        }
                    } footer: {
                        Text(ai.toolsAllowed
                             ? "On — the Copilot can run any NetTactix tool on its own to answer you, including active ones that send traffic to a target. Each tool it runs is shown in the chat."
                             : "Off — the Copilot can only talk; it can't run scans, lookups or any other tool for you.")
                            .font(.caption2)
                    }
                    .listRowBackground(Theme.card)

                    Section {
                        ForEach(ai.conversations) { c in
                            NavigationLink { ChatView(conversation: c) } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(c.title).foregroundStyle(Theme.fg).lineLimit(1)
                                    Text(previewLine(c)).font(.caption).foregroundStyle(Theme.dim).lineLimit(1)
                                }
                            }
                            .listRowBackground(Theme.card)
                            .swipeActions {
                                Button(role: .destructive) {
                                    localModel.forget(conversationID: c.id)
                                    ai.deleteConversation(c)
                                } label: { Label("Delete", systemImage: "trash") }
                            }
                        }
                        if ai.conversations.isEmpty {
                            Text("No chats yet — tap New chat.").font(.caption).foregroundStyle(Theme.dim).listRowBackground(Theme.card)
                        }
                    } header: { Text("Chats").foregroundStyle(Theme.accent) }
                }
                .scrollContentBackground(.hidden)
            }
        }
        .screenBackground()
        .navigationTitle("Copilot")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Menu {
                    Button { managingProviders = true } label: { Label("AI providers", systemImage: "cpu") }
                    if !ai.conversations.isEmpty {
                        Button(role: .destructive) { ai.clearConversations() } label: { Label("Clear all chats", systemImage: "trash") }
                    }
                } label: { Image(systemName: "ellipsis.circle") }
            }
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { startedChat = ai.newConversation(); showChat = true } label: { Image(systemName: "square.and.pencil") }
                    .disabled(ai.providers.isEmpty)
            }
        }
        .navigationDestination(isPresented: $showChat) {
            if let c = startedChat { ChatView(conversation: c) }
        }
        .sheet(isPresented: $addingProvider) { AIProviderEditor(config: AIProviderConfig()) }
        .sheet(isPresented: $managingProviders) { ProviderListView() }
    }

    private var emptyProviders: some View {
        VStack(spacing: 12) {
            Image(systemName: "sparkles").font(.system(size: 44)).foregroundStyle(Theme.accent)
            Text("Add an AI to chat with").font(.headline)
            Text("Connect a local model (LM Studio / Ollama on your computer) or an API key (OpenAI, OpenRouter, Anthropic). It becomes your recon & CTF copilot — fully saved on-device.")
                .font(.caption).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
            Button { addingProvider = true } label: { Label("Add AI provider", systemImage: "plus") }
                .buttonStyle(PrimaryButtonStyle()).frame(maxWidth: 260)
        }.padding(32).frame(maxHeight: .infinity)
    }

    private func previewLine(_ c: AIConversation) -> String {
        c.messages.last(where: { $0.role != "system" })?.content.replacingOccurrences(of: "\n", with: " ") ?? "Empty"
    }
}

/// Manage AI providers.
struct ProviderListView: View {
    @EnvironmentObject private var ai: AIStore
    @Environment(\.dismiss) private var dismiss
    @State private var adding = false
    @State private var editing: AIProviderConfig?
    @State private var showingLocal: LocalModelStore.ModelOption?
    @State private var browsingCatalog = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(ai.providers) { p in
                        HStack(spacing: 10) {
                            Button {
                                withAnimation(.easeInOut(duration: 0.15)) { ai.selectedProviderID = p.id }
                            } label: {
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(spacing: 6) {
                                            Text(p.name).foregroundStyle(Theme.fg)
                                            if p.isLocalModel { Image(systemName: "cpu").font(.caption2).foregroundStyle(Theme.dim) }
                                        }
                                        Text(p.isLocalModel ? "On-device · \(LocalModelStore.option(for: p.model)?.sizeHint ?? "")" : "\(p.model) · \(p.baseURL)")
                                            .font(.caption).foregroundStyle(Theme.dim).lineLimit(1)
                                    }
                                    Spacer()
                                    if ai.selectedProviderID == p.id {
                                        Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.accent)
                                    }
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            Button {
                                if p.isLocalModel {
                                    showingLocal = LocalModelStore.option(for: p.model)
                                } else {
                                    editing = p
                                }
                            } label: {
                                Image(systemName: p.isLocalModel ? "info.circle" : "pencil.circle").foregroundStyle(Theme.dim)
                            }
                            .buttonStyle(.plain)
                        }
                        .listRowBackground(Theme.card)
                        .swipeActions {
                            Button(role: .destructive) { ai.deleteProvider(p) } label: { Label("Delete", systemImage: "trash") }
                        }
                    }
                } footer: {
                    Text("Tap a provider to use it for new chats (saved — it stays selected after relaunch). Tap the icon to edit or manage it.")
                        .font(.caption2)
                }
            }
            .scrollContentBackground(.hidden).background(Theme.bg.ignoresSafeArea())
            .navigationTitle("AI providers").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button { adding = true } label: { Label("Remote provider (API / local server)", systemImage: "network") }
                        Button { browsingCatalog = true } label: { Label("On-device model (offline)", systemImage: "cpu") }
                    } label: { Image(systemName: "plus") }
                }
            }
            .sheet(isPresented: $adding) { AIProviderEditor(config: AIProviderConfig()) }
            .sheet(item: $editing) { c in AIProviderEditor(config: c) }
            .sheet(item: $showingLocal) { opt in NavigationStack { LocalModelView(option: opt) } }
            .sheet(isPresented: $browsingCatalog) { NavigationStack { LocalModelCatalogView() } }
        }
    }
}

/// Browse every on-device model NetTactix offers, grouped by purpose. Tapping one opens its
/// own download/status screen — nothing is added to your providers list just from browsing.
struct LocalModelCatalogView: View {
    @EnvironmentObject private var ai: AIStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            ForEach(LocalModelStore.Category.allCases, id: \.self) { cat in
                let options = LocalModelStore.catalog.filter { $0.category == cat }
                if !options.isEmpty {
                    Section {
                        ForEach(options) { opt in
                            NavigationLink { LocalModelView(option: opt) } label: { row(opt) }
                                .listRowBackground(Theme.card)
                        }
                    } header: { Text(cat.rawValue).foregroundStyle(Theme.accent) }
                }
            }
        }
        .scrollContentBackground(.hidden).background(Theme.bg.ignoresSafeArea())
        .navigationTitle("On-device models").navigationBarTitleDisplayMode(.inline)
        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
    }

    private func row(_ opt: LocalModelStore.ModelOption) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(opt.name).foregroundStyle(Theme.fg)
                    if isAdded(opt) { Image(systemName: "checkmark.circle.fill").font(.caption2).foregroundStyle(Theme.accent) }
                }
                Text(opt.summary).font(.caption).foregroundStyle(Theme.dim).lineLimit(2)
            }
            Spacer()
            if !LocalModelStore.fitsDeviceMemory(opt) {
                Image(systemName: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(Severity.high.color)
            }
            Text(opt.sizeHint).font(.caption2).foregroundStyle(Theme.dim)
        }
    }

    private func isAdded(_ opt: LocalModelStore.ModelOption) -> Bool {
        ai.providers.contains { $0.isLocalModel && $0.model == opt.id }
    }
}

/// Add / edit a provider, with quick presets.
struct AIProviderEditor: View {
    @EnvironmentObject private var ai: AIStore
    @Environment(\.dismiss) private var dismiss
    @State var config: AIProviderConfig
    @State private var apiKey = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Quick start") {
                    Menu {
                        ForEach(Array(AIProviderConfig.presets.enumerated()), id: \.offset) { _, p in
                            Button(p.name) { apply(p) }
                        }
                    } label: { Label("Choose a preset…", systemImage: "wand.and.stars") }
                }
                Section("Provider") {
                    TextField("Name", text: $config.name).textInputAutocapitalization(.words)
                    Picker("API shape", selection: $config.shape) {
                        ForEach(AIClient.Shape.allCases, id: \.self) { Text($0 == .openAI ? "OpenAI-compatible" : "Anthropic").tag($0) }
                    }
                    TextField("Base URL", text: $config.baseURL)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    TextField("Model", text: $config.model).textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("API key (leave blank for local servers)", text: $apiKey)
                    Toggle("Save key in Keychain", isOn: $config.savesKey)
                }
                Section {
                    Text("Local models: run LM Studio or Ollama on a computer on the same Wi-Fi, start its server, and use that computer's LAN IP (not localhost). Make sure the server listens on 0.0.0.0.")
                        .font(.caption).foregroundStyle(Theme.dim)
                }
            }
            .scrollContentBackground(.hidden).background(Theme.bg.ignoresSafeArea())
            .navigationTitle(config.name.isEmpty ? "New provider" : config.name).navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("Save") { save() }.disabled(!config.isValid) }
            }
            .onAppear { apiKey = ai.key(for: config.id) ?? "" }
        }
    }

    private func apply(_ p: AIProviderConfig.Preset) {
        config.name = p.name; config.shape = p.shape; config.baseURL = p.baseURL; config.model = p.model
    }
    private func save() { ai.upsert(config, key: config.savesKey ? apiKey : nil); dismiss() }
}

/// Download/load status and management for the on-device (MLX) model — a real inference
/// engine runs entirely on your phone, no network request or API key involved.
struct LocalModelView: View {
    let option: LocalModelStore.ModelOption
    @EnvironmentObject private var ai: AIStore
    @EnvironmentObject private var localModel: LocalModelStore
    @Environment(\.dismiss) private var dismiss
    @State private var showingMemoryWarning = false

    private var existingProvider: AIProviderConfig? {
        ai.providers.first { $0.isLocalModel && $0.model == option.id }
    }
    private var fitsDeviceMemory: Bool { LocalModelStore.fitsDeviceMemory(option) }

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "cpu").font(.system(size: 44)).foregroundStyle(Theme.accent)
            Text(option.id).font(.system(.callout, design: .monospaced)).multilineTextAlignment(.center)
            Text("\(option.summary) Runs fully on this device — no network request, no API key, works offline once downloaded. \(option.sizeHint) download, cached afterwards. Needs a modern iPhone with several GB of free storage; noticeably slower and lower-quality than a cloud API.")
                .font(.caption).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
            if !fitsDeviceMemory {
                Label("This device has ≈\(Int(LocalModelStore.deviceRAMGB)) GB of RAM; this model needs roughly \(Int(LocalModelStore.recommendedRAMGB(option))) GB free to load safely and may crash the app — or make the whole phone unresponsive — if it doesn't fit.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2).foregroundStyle(Severity.high.color).multilineTextAlignment(.center)
            }

            statusView
            Spacer()
        }
        .padding(24)
        .screenBackground()
        .navigationTitle(option.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
        .alert("This model may be too large for this device", isPresented: $showingMemoryWarning) {
            Button("Cancel", role: .cancel) {}
            Button("Download anyway", role: .destructive) { startLoad() }
        } message: {
            Text("This device has ≈\(Int(LocalModelStore.deviceRAMGB)) GB of RAM and this model needs roughly \(Int(LocalModelStore.recommendedRAMGB(option))) GB free to load safely. Continuing may crash NetTactix or make the whole phone briefly unresponsive while it tries.")
        }
    }

    @ViewBuilder private var statusView: some View {
        switch localModel.status(for: option.id) {
        case .notDownloaded:
            Button {
                if fitsDeviceMemory { startLoad() } else { showingMemoryWarning = true }
            } label: { Label("Download & load (\(option.sizeHint))", systemImage: "arrow.down.circle") }
                .buttonStyle(PrimaryButtonStyle())
        case .working:
            VStack(spacing: 8) {
                ProgressView()
                Text("Downloading / preparing — this can take several minutes on first run. Keep NetTactix open (even in the background) until this finishes; fully closing the app will stop it.")
                    .font(.caption).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
                Button(role: .destructive) { localModel.cancel(modelID: option.id) } label: { Text("Cancel") }
                    .font(.caption).buttonStyle(.plain).padding(.top, 4)
            }
        case .ready:
            VStack(spacing: 12) {
                Label("Ready", systemImage: "checkmark.circle.fill").foregroundStyle(Theme.accent)
                Button { useForNewChats() } label: { Label("Use for new chats", systemImage: "checkmark") }
                    .buttonStyle(PrimaryButtonStyle())
            }
        case .failed(let message):
            VStack(spacing: 12) {
                Label(message, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(Severity.high.color).multilineTextAlignment(.center)
                Button { if fitsDeviceMemory { startLoad() } else { showingMemoryWarning = true } } label: { Label("Retry", systemImage: "arrow.clockwise") }
                    .buttonStyle(PrimaryButtonStyle())
            }
        }
    }

    /// Requests extra execution time from iOS so briefly backgrounding the app (switching
    /// away for a moment, a notification) doesn't get an in-flight download killed outright —
    /// a real but bounded grace period, not indefinite background operation. Fully force-
    /// quitting the app still stops it; there's no way around that without a background-
    /// transfer architecture this third-party model downloader doesn't expose.
    private func startLoad() {
        ensureProviderExists()
        var taskID: UIBackgroundTaskIdentifier = .invalid
        taskID = UIApplication.shared.beginBackgroundTask(withName: "nettactix.ai.modelDownload") {
            UIApplication.shared.endBackgroundTask(taskID)
            taskID = .invalid
        }
        Task {
            try? await localModel.ensureLoaded(modelID: option.id)
            if taskID != .invalid {
                UIApplication.shared.endBackgroundTask(taskID)
                taskID = .invalid
            }
        }
    }

    private func useForNewChats() {
        let provider = ensureProviderExists()
        ai.selectedProviderID = provider.id
        dismiss()
    }

    @discardableResult
    private func ensureProviderExists() -> AIProviderConfig {
        if let existing = existingProvider { return existing }
        let c = AIProviderConfig.localModel(option)
        ai.upsert(c, key: nil)
        return c
    }
}
