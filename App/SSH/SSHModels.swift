import Foundation

/// A saved SSH connection profile. Secrets (password / private key / passphrase)
/// are never stored in this struct — they live in the Keychain, keyed by `id`.
struct SSHHost: Identifiable, Codable, Equatable {
    enum Auth: String, Codable, CaseIterable, Identifiable {
        case password
        case privateKey
        var id: String { rawValue }
        var label: String { self == .password ? "Password" : "Private key" }
    }

    var id: UUID = UUID()
    var name: String = ""
    var host: String = ""
    var port: Int = 22
    var username: String = ""
    var auth: Auth = .password
    /// Remember the secret in the Keychain between launches.
    var savePassword: Bool = true
    var lastUsed: Date?

    /// A friendly label, falling back to user@host.
    var displayName: String {
        let n = name.trimmingCharacters(in: .whitespaces)
        if !n.isEmpty { return n }
        let u = username.trimmingCharacters(in: .whitespaces)
        return u.isEmpty ? host : "\(u)@\(host)"
    }

    var endpoint: String { "\(username.isEmpty ? "" : username + "@")\(host):\(port)" }

    var isValid: Bool {
        !host.trimmingCharacters(in: .whitespaces).isEmpty &&
        !username.trimmingCharacters(in: .whitespaces).isEmpty &&
        (1...65535).contains(port)
    }
}
