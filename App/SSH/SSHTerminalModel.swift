import Foundation
import SwiftUI
#if canImport(Citadel)
import Citadel
import NIOCore
import Crypto
#endif

/// Drives one live SSH shell: connects, streams output into `screen`, and
/// forwards typed input. Interactive — a persistent remote shell, so `cd`,
/// environment and history are kept for the life of the connection.
@MainActor
final class SSHTerminalModel: ObservableObject {
    enum Phase: Equatable {
        case idle, connecting, connected, failed(String), closed
    }

    @Published var phase: Phase = .idle
    @Published var screen: String = ""
    @Published var host: SSHHost
    /// Whether the connect/shell pipeline is busy enough to disable the input.
    var isLive: Bool { phase == .connected }

    private let maxScreen = 240_000

    #if canImport(Citadel)
    private var client: SSHClient?
    private var stdin: TTYStdinWriter?
    private var pump: Task<Void, Never>?
    private var leftover = Data()
    #endif

    init(host: SSHHost) { self.host = host }

    // MARK: Lifecycle

    func connect(password: String?, privateKey: String?, passphrase: String?) {
        #if canImport(Citadel)
        guard phase != .connecting, phase != .connected else { return }
        phase = .connecting
        append("Connecting to \(host.endpoint)…\n")
        let h = host
        pump = Task { [weak self] in
            do {
                let auth = try Self.makeAuth(host: h, password: password, privateKey: privateKey, passphrase: passphrase)
                let client = try await SSHClient.connect(
                    host: h.host,
                    port: h.port,
                    authenticationMethod: auth,
                    hostKeyValidator: .acceptAnything(),
                    reconnect: .never,
                    connectTimeout: .seconds(20)
                )
                await self?.setClient(client)
                await self?.mark(.connected, note: "Connected. Opening shell…\n")
                try await client.withTTY { inbound, outbound in
                    await self?.setStdin(outbound)
                    try? await outbound.changeSize(cols: 80, rows: 24, pixelWidth: 0, pixelHeight: 0)
                    for try await chunk in inbound {
                        if Task.isCancelled { break }
                        switch chunk {
                        case .stdout(let b), .stderr(let b):
                            if let bytes = b.getBytes(at: b.readerIndex, length: b.readableBytes) {
                                await self?.feed(bytes)
                            }
                        }
                    }
                }
                await self?.mark(.closed, note: "\n[session closed]\n")
                try? await client.close()
            } catch is CancellationError {
                // user-initiated disconnect
            } catch {
                await self?.mark(.failed(Self.describe(error)), note: "\n[error] \(Self.describe(error))\n")
            }
        }
        #else
        phase = .failed("SSH is unavailable in this build.")
        append("SSH client library not available in this build.\n")
        #endif
    }

    func send(_ text: String) {
        #if canImport(Citadel)
        guard let stdin else { return }
        let data = ByteBuffer(string: text)
        Task { try? await stdin.write(data) }
        #endif
    }

    /// Send a line of input (appends a newline / carriage return).
    func sendLine(_ line: String) { send(line + "\n") }

    /// Send a control character, e.g. Ctrl-C (0x03), Ctrl-D (0x04), Ctrl-Z (0x1A).
    func sendControl(_ scalar: UInt8) {
        #if canImport(Citadel)
        guard let stdin else { return }
        var buf = ByteBuffer()
        buf.writeInteger(scalar)
        Task { try? await stdin.write(buf) }
        #endif
    }

    func disconnect() {
        #if canImport(Citadel)
        pump?.cancel()
        pump = nil
        let c = client
        client = nil
        stdin = nil
        Task { try? await c?.close() }
        #endif
        if phase == .connected || phase == .connecting { phase = .closed }
    }

    func clearScreen() { screen = "" }

    // MARK: Internal state hops

    #if canImport(Citadel)
    private func setClient(_ c: SSHClient) { self.client = c }
    private func setStdin(_ w: TTYStdinWriter) { self.stdin = w }

    private func feed(_ bytes: [UInt8]) {
        leftover.append(contentsOf: bytes)
        // Decode as much valid UTF-8 as we can; keep any trailing partial multibyte sequence.
        var cut = leftover.count
        while cut > 0 {
            if let s = String(data: leftover.prefix(cut), encoding: .utf8) {
                append(Self.sanitize(s))
                leftover.removeFirst(cut)
                return
            }
            cut -= 1
        }
        // Nothing decodable yet (rare); guard against unbounded growth.
        if leftover.count > 8 { leftover.removeAll() }
    }
    #endif

    private func mark(_ p: Phase, note: String) {
        phase = p
        if !note.isEmpty { append(note) }
    }

    private func append(_ s: String) {
        screen += s
        if screen.count > maxScreen { screen.removeFirst(screen.count - maxScreen) }
    }

    // MARK: Helpers

    #if canImport(Citadel)
    private static func makeAuth(host: SSHHost, password: String?, privateKey: String?, passphrase: String?) throws -> SSHAuthenticationMethod {
        switch host.auth {
        case .password:
            return .passwordBased(username: host.username, password: password ?? "")
        case .privateKey:
            let key = privateKey ?? ""
            let decrypt = (passphrase?.isEmpty == false) ? Data(passphrase!.utf8) : nil
            // OpenSSH keys declare their type in the body; try ed25519 then RSA.
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

    private static func describe(_ error: Error) -> String {
        let s = "\(error)"
        if s.contains("authenticationFailed") || s.lowercased().contains("auth") { return "Authentication failed — check username and password/key." }
        if s.contains("connectTimeout") || s.lowercased().contains("timed out") { return "Connection timed out — host unreachable or port closed." }
        if s.contains("connectionClosed") { return "Connection closed by the host." }
        return s
    }
    #endif

    /// Strip ANSI/VT escape sequences and non-printable control bytes, keeping text, \n and \t.
    static func sanitize(_ input: String) -> String {
        var out = String()
        out.reserveCapacity(input.count)
        let scalars = Array(input.unicodeScalars)
        var i = 0
        while i < scalars.count {
            let s = scalars[i]
            if s == "\u{1B}" { // ESC
                let next = i + 1 < scalars.count ? scalars[i + 1] : "\u{0}"
                if next == "[" { // CSI ... final byte @-~
                    i += 2
                    while i < scalars.count {
                        let c = scalars[i]; i += 1
                        if c.value >= 0x40 && c.value <= 0x7E { break }
                    }
                    continue
                } else if next == "]" { // OSC ... BEL or ST
                    i += 2
                    while i < scalars.count {
                        let c = scalars[i]
                        if c == "\u{07}" { i += 1; break }
                        if c == "\u{1B}" && i + 1 < scalars.count && scalars[i + 1] == "\\" { i += 2; break }
                        i += 1
                    }
                    continue
                } else { // other 2-char escape
                    i += 2
                    continue
                }
            }
            if s == "\n" || s == "\t" {
                out.unicodeScalars.append(s)
            } else if s == "\r" {
                // keep carriage returns out; most servers send \r\n
            } else if s == "\u{08}" { // backspace
                if !out.isEmpty { out.removeLast() }
            } else if s.value >= 0x20 || s.value == 0x09 {
                out.unicodeScalars.append(s)
            }
            i += 1
        }
        return out
    }
}
