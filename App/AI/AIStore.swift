import SwiftUI
import Security
import ReconCore

/// A saved AI provider (endpoint + model). The API key, if any, lives in the Keychain.
struct AIProviderConfig: Identifiable, Codable, Equatable {
    var id = UUID()
    var name: String = ""
    var shape: AIClient.Shape = .openAI
    var baseURL: String = ""
    var model: String = ""
    var temperature: Double = 0.4
    var savesKey: Bool = true
    /// Runs fully on-device via MLX instead of talking to a network endpoint — baseURL/apiKey/
    /// shape are unused when this is true. Optional so configs saved before this field existed
    /// still decode (a missing value means false, i.e. an ordinary remote provider).
    var isLocal: Bool?
    var isLocalModel: Bool { isLocal ?? false }

    var isValid: Bool {
        guard !name.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        if isLocalModel { return true }
        return !baseURL.trimmingCharacters(in: .whitespaces).isEmpty &&
               !model.trimmingCharacters(in: .whitespaces).isEmpty
    }

    static func localModel(_ option: LocalModelStore.ModelOption) -> AIProviderConfig {
        var c = AIProviderConfig()
        c.name = "\(option.name) (offline)"
        c.isLocal = true
        c.model = option.id
        c.savesKey = false
        return c
    }

    struct Preset { let name: String; let shape: AIClient.Shape; let baseURL: String; let model: String; let needsKey: Bool; let hint: String }
    static let presets: [Preset] = [
        Preset(name: "LM Studio (local)", shape: .openAI, baseURL: "http://192.168.1.50:1234/v1", model: "", needsKey: false,
               hint: "Run LM Studio on your computer, start its server, and use that computer's LAN IP. Model = the one you loaded."),
        Preset(name: "Ollama (local)", shape: .openAI, baseURL: "http://192.168.1.50:11434/v1", model: "llama3.1", needsKey: false,
               hint: "Run `ollama serve` with OLLAMA_HOST=0.0.0.0, use the computer's LAN IP."),
        Preset(name: "OpenAI", shape: .openAI, baseURL: "https://api.openai.com/v1", model: "gpt-4o-mini", needsKey: true,
               hint: "Needs an OpenAI API key."),
        Preset(name: "OpenRouter", shape: .openAI, baseURL: "https://openrouter.ai/api/v1", model: "openai/gpt-4o-mini", needsKey: true,
               hint: "One key, many models."),
        Preset(name: "Anthropic (Claude)", shape: .anthropic, baseURL: "https://api.anthropic.com/v1", model: "claude-3-5-sonnet-latest", needsKey: true,
               hint: "Needs an Anthropic API key."),
    ]
}

struct AIConversation: Identifiable, Codable, Equatable {
    struct Msg: Identifiable, Codable, Equatable {
        var id = UUID()
        var role: String        // user | assistant | system
        var content: String
        var date: Date = Date()
    }
    var id = UUID()
    var title: String = "New chat"
    var providerID: UUID?
    var messages: [Msg] = []
    var updated: Date = Date()
}

@MainActor
final class AIStore: ObservableObject {
    @Published private(set) var providers: [AIProviderConfig] = []
    @Published private(set) var conversations: [AIConversation] = []
    /// The last-used provider, persisted across launches and reused for every new chat —
    /// backed directly by UserDefaults (not @Published/@AppStorage) since @AppStorage on a
    /// plain ObservableObject doesn't reliably trigger view updates; the explicit
    /// objectWillChange.send() in the setter below does.
    var selectedProviderID: UUID? {
        get { UUID(uuidString: selectedProviderIDRaw) }
        set {
            objectWillChange.send()
            selectedProviderIDRaw = newValue?.uuidString ?? ""
        }
    }
    @AppStorage("nettactix.ai.selectedProviderID") private var selectedProviderIDRaw: String = ""
    /// The single permission gate for tool use: off by default. When on, the Copilot may
    /// call any NetTactix tool on its own — including active ones that send real traffic —
    /// without a confirmation per call, so the toggle itself is the "given permission".
    @AppStorage("nettactix.ai.toolsAllowed") var toolsAllowed: Bool = false

    private static let service = "com.nettactix.ai"
    private let provURL: URL
    private let convURL: URL

    init() {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        provURL = dir.appendingPathComponent("ai_providers.json")
        convURL = dir.appendingPathComponent("ai_conversations.json")
        load()
        // Only fall back to the first provider if nothing was ever selected (fresh install)
        // or the persisted id no longer matches any saved provider (e.g. it was deleted).
        if selectedProviderID == nil || !providers.contains(where: { $0.id == selectedProviderID }) {
            selectedProviderID = providers.first?.id
        }
    }

    var selectedProvider: AIProviderConfig? { providers.first { $0.id == selectedProviderID } }

    // MARK: Providers

    func upsert(_ p: AIProviderConfig, key: String?) {
        if let i = providers.firstIndex(where: { $0.id == p.id }) { providers[i] = p }
        else { providers.append(p); if selectedProviderID == nil { selectedProviderID = p.id } }
        if p.savesKey { setKey(key, for: p.id) } else { setKey(nil, for: p.id) }
        saveProviders()
    }

    func deleteProvider(_ p: AIProviderConfig) {
        providers.removeAll { $0.id == p.id }
        setKey(nil, for: p.id)
        if selectedProviderID == p.id { selectedProviderID = providers.first?.id }
        saveProviders()
    }

    /// Build the runtime provider (with key) for a config.
    func runtime(_ c: AIProviderConfig) -> AIClient.Provider {
        AIClient.Provider(shape: c.shape, baseURL: c.baseURL, apiKey: key(for: c.id), model: c.model, temperature: c.temperature)
    }

    // MARK: Conversations

    @discardableResult
    func newConversation() -> AIConversation {
        var c = AIConversation()
        c.providerID = selectedProviderID
        conversations.insert(c, at: 0)
        saveConversations()
        return c
    }

    func update(_ c: AIConversation) {
        guard let i = conversations.firstIndex(where: { $0.id == c.id }) else { return }
        var updated = c
        updated.updated = Date()
        conversations[i] = updated
        // Keep most-recent first.
        conversations.sort { $0.updated > $1.updated }
        saveConversations()
    }

    func deleteConversation(_ c: AIConversation) {
        conversations.removeAll { $0.id == c.id }
        saveConversations()
    }

    func clearConversations() { conversations.removeAll(); saveConversations() }

    // MARK: Tool execution bridge

    /// Runs one NetTactix tool by id for the Copilot and renders its output back to plain
    /// text. Never throws — a bad id, a timeout or a tool failure all become a result the
    /// model can read and react to, same as any other tool-calling agent. A free static
    /// function (rather than an instance method) so it never captures the (non-Sendable)
    /// store instance when handed to AIClient.agentComplete as a @Sendable closure.
    ///
    /// Wrapped in a watchdog: a single hung tool (e.g. a scan against an unreachable host)
    /// would otherwise block the whole agent loop indefinitely, since tools don't all take
    /// a timeout of their own. 60s is generous for any single lookup/scan step.
    static func executeTool(id: String, input: String) async -> String {
        guard let spec = ToolCatalog.spec(id: id) else {
            let known = ToolCatalog.all.map(\.id).joined(separator: ", ")
            return "error: no tool with id \"\(id)\". Known ids: \(known)"
        }
        let ctx = ToolContext(secrets: KeychainSecrets())
        struct ToolTimedOut: Error {}
        do {
            return try await withThrowingTaskGroup(of: String.self) { group in
                group.addTask {
                    let output = try await spec.run(input, ctx)
                    return output.renderCompact()
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: 60_000_000_000)
                    throw ToolTimedOut()
                }
                let first = try await group.next()!
                group.cancelAll()
                return first
            }
        } catch is ToolTimedOut {
            return "error running \(spec.title): timed out after 60s"
        } catch {
            return "error running \(spec.title): \((error as? ReconError)?.errorDescription ?? "\(error)")"
        }
    }

    // MARK: Persistence

    private func load() {
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        if let d = try? Data(contentsOf: provURL) { providers = (try? dec.decode([AIProviderConfig].self, from: d)) ?? [] }
        if let d = try? Data(contentsOf: convURL) { conversations = (try? dec.decode([AIConversation].self, from: d)) ?? [] }
    }
    private func saveProviders() { write(providers, to: provURL) }
    private func saveConversations() { write(conversations, to: convURL) }
    private func write<T: Encodable>(_ value: T, to url: URL) {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        if let d = try? enc.encode(value) { try? d.write(to: url, options: [.atomic, .completeFileProtection]) }
    }

    // MARK: Keychain

    func key(for id: UUID) -> String? { getKey(id) }

    private func setKey(_ value: String?, for id: UUID) {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                   kSecAttrService as String: Self.service,
                                   kSecAttrAccount as String: id.uuidString]
        SecItemDelete(base as CFDictionary)
        let v = (value ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !v.isEmpty else { return }
        var add = base
        add[kSecValueData as String] = Data(v.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }
    private func getKey(_ id: UUID) -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: Self.service,
                                kSecAttrAccount as String: id.uuidString,
                                kSecReturnData as String: true,
                                kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let d = item as? Data, let s = String(data: d, encoding: .utf8), !s.isEmpty else { return nil }
        return s
    }
}
