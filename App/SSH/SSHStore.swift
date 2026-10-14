import SwiftUI
import Security

/// Saved SSH hosts + their secrets. Profiles persist to Documents/ssh_hosts.json;
/// secrets are kept only in the iOS Keychain (device-only, file-protected).
@MainActor
final class SSHStore: ObservableObject {
    @Published private(set) var hosts: [SSHHost] = []

    private let url: URL = {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("ssh_hosts.json")
    }()

    private static let service = "com.reconkit.ssh"

    init() { load() }

    // MARK: Profiles

    func upsert(_ host: SSHHost) {
        if let i = hosts.firstIndex(where: { $0.id == host.id }) {
            hosts[i] = host
        } else {
            hosts.insert(host, at: 0)
        }
        save()
    }

    func delete(_ host: SSHHost) {
        hosts.removeAll { $0.id == host.id }
        deleteSecret(host.id, suffix: "pw")
        deleteSecret(host.id, suffix: "key")
        deleteSecret(host.id, suffix: "pass")
        save()
    }

    func markUsed(_ host: SSHHost) {
        guard let i = hosts.firstIndex(where: { $0.id == host.id }) else { return }
        hosts[i].lastUsed = Date()
        let used = hosts.remove(at: i)
        hosts.insert(used, at: 0)
        save()
    }

    // MARK: Secrets (Keychain)

    func setPassword(_ value: String?, for id: UUID) { setSecret(value, id, suffix: "pw") }
    func password(for id: UUID) -> String? { getSecret(id, suffix: "pw") }

    func setPrivateKey(_ value: String?, for id: UUID) { setSecret(value, id, suffix: "key") }
    func privateKey(for id: UUID) -> String? { getSecret(id, suffix: "key") }

    func setPassphrase(_ value: String?, for id: UUID) { setSecret(value, id, suffix: "pass") }
    func passphrase(for id: UUID) -> String? { getSecret(id, suffix: "pass") }

    // MARK: Persistence

    private func load() {
        guard let data = try? Data(contentsOf: url) else { return }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        hosts = (try? dec.decode([SSHHost].self, from: data)) ?? []
    }

    private func save() {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        if let data = try? enc.encode(hosts) {
            try? data.write(to: url, options: [.atomic, .completeFileProtection])
        }
    }

    // MARK: Keychain helpers

    private func account(_ id: UUID, _ suffix: String) -> String { "\(id.uuidString).\(suffix)" }

    private func setSecret(_ value: String?, _ id: UUID, suffix: String) {
        let acct = account(id, suffix)
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: acct
        ]
        SecItemDelete(base as CFDictionary)
        let trimmed = (value ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var add = base
        add[kSecValueData as String] = Data(trimmed.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }

    private func getSecret(_ id: UUID, suffix: String) -> String? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account(id, suffix),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data, let s = String(data: data, encoding: .utf8), !s.isEmpty else { return nil }
        return s
    }

    private func deleteSecret(_ id: UUID, suffix: String) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account(id, suffix)
        ]
        SecItemDelete(base as CFDictionary)
    }
}
