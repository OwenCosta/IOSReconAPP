import Foundation
#if canImport(Citadel)
import Citadel
import Crypto

/// Shared SSH connection + auth helpers used by both the terminal and the SFTP browser.
enum SSHConnect {
    static func makeAuth(host: SSHHost, password: String?, privateKey: String?, passphrase: String?) throws -> SSHAuthenticationMethod {
        switch host.auth {
        case .password:
            return .passwordBased(username: host.username, password: password ?? "")
        case .privateKey:
            let key = privateKey ?? ""
            let decrypt = (passphrase?.isEmpty == false) ? Data(passphrase!.utf8) : nil
            if key.contains("ssh-ed25519") || key.lowercased().contains("ed25519") {
                let pk = try Curve25519.Signing.PrivateKey(sshEd25519: key, decryptionKey: decrypt)
                return .ed25519(username: host.username, privateKey: pk)
            }
            do {
                let pk = try Insecure.RSA.PrivateKey(sshRsa: key, decryptionKey: decrypt)
                return .rsa(username: host.username, privateKey: pk)
            } catch {
                let pk = try Curve25519.Signing.PrivateKey(sshEd25519: key, decryptionKey: decrypt)
                return .ed25519(username: host.username, privateKey: pk)
            }
        }
    }

    static func connect(host: SSHHost, password: String?, privateKey: String?, passphrase: String?,
                        timeout: Int64 = 20) async throws -> SSHClient {
        let auth = try makeAuth(host: host, password: password, privateKey: privateKey, passphrase: passphrase)
        // TODO: this is NOT trust-on-first-use — it accepts any host key, every connection, with
        // nothing remembered or compared between attempts. Real TOFU needs a persisted per-host
        // key fingerprint (Keychain) checked via SSHHostKeyValidator.custom(_:), which in turn
        // needs a way to get stable bytes out of the NIOSSHPublicKey swift-nio-ssh hands the
        // validator — not exposed publicly as of swift-nio-ssh's current API, so this is left as
        // a real known gap rather than a false claim. The Terminal screen's footer says so.
        return try await SSHClient.connect(
            host: host.host,
            port: host.port,
            authenticationMethod: auth,
            hostKeyValidator: .acceptAnything(),
            reconnect: .never,
            connectTimeout: .seconds(timeout)
        )
    }

    static func describe(_ error: Error) -> String {
        let s = "\(error)"
        if s.contains("authenticationFailed") || s.lowercased().contains("auth") { return "Authentication failed. Check username and password/key." }
        if s.contains("connectTimeout") || s.lowercased().contains("timed out") { return "Connection timed out. Host unreachable or port closed." }
        if s.contains("connectionClosed") { return "Connection closed by the host." }
        return s
    }
}
#endif
