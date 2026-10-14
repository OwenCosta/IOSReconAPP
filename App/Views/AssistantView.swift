import SwiftUI
import ReconCore

/// Conversation list + entry to the AI assistant. Pushed from the dashboard.
struct AssistantHomeView: View {
    @EnvironmentObject private var ai: AIStore
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
                            .swipeActions { Button(role: .destructive) { ai.deleteConversation(c) } label: { Label("Delete", systemImage: "trash") } }
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
                                        Text(p.name).foregroundStyle(Theme.fg)
                                        Text("\(p.model) · \(p.baseURL)").font(.caption).foregroundStyle(Theme.dim).lineLimit(1)
                                    }
                                    Spacer()
                                    if ai.selectedProviderID == p.id {
                                        Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.accent)
                                    }
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            Button { editing = p } label: {
                                Image(systemName: "pencil.circle").foregroundStyle(Theme.dim)
                            }
                            .buttonStyle(.plain)
                        }
                        .listRowBackground(Theme.card)
                        .swipeActions {
                            Button(role: .destructive) { ai.deleteProvider(p) } label: { Label("Delete", systemImage: "trash") }
                        }
                    }
                } footer: {
                    Text("Tap a provider to use it for new chats (saved — it stays selected after relaunch). Tap the pencil to edit.")
                        .font(.caption2)
                }
            }
            .scrollContentBackground(.hidden).background(Theme.bg.ignoresSafeArea())
            .navigationTitle("AI providers").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .navigationBarTrailing) { Button { adding = true } label: { Image(systemName: "plus") } }
            }
            .sheet(isPresented: $adding) { AIProviderEditor(config: AIProviderConfig()) }
            .sheet(item: $editing) { c in AIProviderEditor(config: c) }
        }
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
