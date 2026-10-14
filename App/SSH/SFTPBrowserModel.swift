import Foundation
import SwiftUI
#if canImport(Citadel)
import Citadel
import NIOCore
#endif

/// Browses a remote filesystem over SFTP (same credentials as the SSH terminal)
/// and downloads files to the device for viewing / sharing. Phone-only file access.
@MainActor
final class SFTPBrowserModel: ObservableObject {
    struct Entry: Identifiable, Equatable {
        let id = UUID()
        let name: String
        let isDir: Bool
        let isLink: Bool
        let size: UInt64?
        let perms: String
        var icon: String { isDir ? "folder.fill" : (isLink ? "arrow.up.right.square" : "doc") }
        var sizeText: String { isDir ? "" : (size.map(SFTPBrowserModel.humanSize) ?? "") }
    }

    enum Phase: Equatable { case idle, connecting, ready, failed(String) }

    @Published var phase: Phase = .idle
    @Published var entries: [Entry] = []
    @Published var busy = false
    @Published var error: String?
    /// Directory names from the starting directory (home), for the breadcrumb/path.
    @Published private(set) var stack: [String] = []
    /// A file just downloaded, ready to share.
    @Published var downloaded: URL?

    let host: SSHHost
    var displayPath: String { "~/" + stack.joined(separator: "/") }

    private let maxDownload: UInt64 = 25 * 1024 * 1024

    #if canImport(Citadel)
    private var client: SSHClient?
    private var sftp: SFTPClient?
    #endif

    init(host: SSHHost) { self.host = host }

    private var remotePath: String { stack.isEmpty ? "." : "./" + stack.joined(separator: "/") }

    // MARK: Lifecycle

    func connect(password: String?, privateKey: String?, passphrase: String?) {
        #if canImport(Citadel)
        guard phase == .idle || isFailed else { return }
        phase = .connecting
        error = nil
        Task { [weak self] in
            guard let self else { return }
            do {
                let client = try await SSHConnect.connect(host: host, password: password, privateKey: privateKey, passphrase: passphrase)
                let sftp = try await client.openSFTP()
                await self.store(client: client, sftp: sftp)
                await self.list()
            } catch {
                await self.fail(SSHConnect.describe(error))
            }
        }
        #else
        phase = .failed("SFTP is unavailable in this build.")
        #endif
    }

    func enter(_ entry: Entry) {
        guard entry.isDir else { return }
        stack.append(entry.name)
        Task { await list() }
    }

    func up() {
        guard !stack.isEmpty else { return }
        stack.removeLast()
        Task { await list() }
    }

    func refresh() { Task { await list() } }

    func disconnect() {
        #if canImport(Citadel)
        let s = sftp; let c = client
        sftp = nil; client = nil
        Task { try? await s?.close(); try? await c?.close() }
        #endif
    }

    // MARK: SFTP ops

    private func list() async {
        #if canImport(Citadel)
        guard let sftp else { return }
        busy = true; error = nil
        do {
            let names = try await sftp.listDirectory(atPath: remotePath)
            let comps = names.flatMap { $0.components }
            var result: [Entry] = []
            for c in comps where c.filename != "." && c.filename != ".." {
                let long = c.longname
                let kind = long.first.map(Character.init) ?? " "
                let isDir = kind == "d" || ((c.attributes.permissions ?? 0) & 0o170000) == 0o040000
                let isLink = kind == "l"
                result.append(Entry(name: c.filename, isDir: isDir, isLink: isLink,
                                    size: c.attributes.size, perms: String(long.prefix(10))))
            }
            result.sort { a, b in a.isDir != b.isDir ? a.isDir && !b.isDir : a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending }
            entries = result
            phase = .ready
        } catch {
            error = SSHConnect.describe(error)
            if phase == .connecting { phase = .failed(error ?? "failed") }
        }
        busy = false
        #endif
    }

    func download(_ entry: Entry) {
        #if canImport(Citadel)
        guard let sftp, !entry.isDir else { return }
        if let sz = entry.size, sz > maxDownload {
            error = "File is \(Self.humanSize(sz)); downloads are capped at 25 MB."
            return
        }
        busy = true; error = nil
        let path = remotePath + "/" + entry.name
        let name = entry.name
        Task { [weak self] in
            guard let self else { return }
            do {
                let file = try await sftp.openFile(filePath: path, flags: .read)
                let buf = try await file.readAll()
                try? await file.close()
                // Convert via NIOCore only (avoid Data(buffer:) from NIOFoundationCompat,
                // which Xcode's explicit-module build does not expose transitively).
                let bytes = buf.getBytes(at: buf.readerIndex, length: buf.readableBytes) ?? []
                let data = Data(bytes)
                let url = try await self.saveDownload(name: name, data: data)
                await self.finishDownload(url: url)
            } catch {
                await self.fail(download: SSHConnect.describe(error))
            }
        }
        #endif
    }

    // MARK: State hops

    #if canImport(Citadel)
    private func store(client: SSHClient, sftp: SFTPClient) { self.client = client; self.sftp = sftp }
    #endif
    private func fail(_ msg: String) { phase = .failed(msg); error = msg }
    private func fail(download msg: String) { error = msg; busy = false }
    private func finishDownload(url: URL) { downloaded = url; busy = false }
    private var isFailed: Bool { if case .failed = phase { return true }; return false }

    private func saveDownload(name: String, data: Data) throws -> URL {
        let dir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("sftp-downloads", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let safe = name.isEmpty ? "download" : name
        let url = dir.appendingPathComponent(safe)
        try data.write(to: url, options: .atomic)
        return url
    }

    static func humanSize(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var v = Double(bytes); var i = 0
        while v >= 1024 && i < units.count - 1 { v /= 1024; i += 1 }
        return i == 0 ? "\(bytes) B" : String(format: "%.1f %@", v, units[i])
    }
}
