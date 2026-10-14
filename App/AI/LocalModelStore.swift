import Foundation
import MLXLLM
import MLXLMCommon
import MLXHuggingFace
import HuggingFace
import Tokenizers

/// Runs a quantised LLM entirely on-device via Apple's MLX framework — no network request, no
/// API key, works fully offline once downloaded. The one model NetTactix offers is a 4-bit
/// quantised ~7B-parameter instruct model (good quality for its size, well-supported chat
/// template), roughly 4.3 GB on first download and cached locally afterwards.
///
/// Needs a real Apple-silicon-class iPhone (A-series Neural Engine/GPU via Metal) with enough
/// free storage and RAM — this is genuinely heavier than any of NetTactix's other tools, and
/// noticeably slower and lower-quality than a cloud API. It's offered for when you want the
/// Copilot to work with no network connection and no API key at all.
///
/// Session note: MLX's ChatSession keeps its own internal conversation context, and there's no
/// documented way to rehydrate that context from an arbitrary external message history — so
/// each AIConversation gets one ChatSession for as long as the app process stays alive. Within
/// one continuous app session the model keeps full multi-turn context; a full relaunch starts
/// the model's own memory of the conversation fresh (the on-screen chat history itself is
/// completely unaffected — only what the model "remembers" resets).
@MainActor
final class LocalModelStore: ObservableObject {
    enum Status: Equatable {
        case notDownloaded
        /// Covers both "downloading" and "loading an already-downloaded model into memory" —
        /// MLX's loader doesn't expose a way to tell these apart or report numeric progress.
        case working
        case ready
        case failed(String)
    }

    static let modelID = "mlx-community/Qwen2.5-7B-Instruct-4bit"
    static let modelSizeHint = "≈4.3 GB"

    @Published private(set) var status: Status = .notDownloaded
    private var container: ModelContainer?
    private var loadTask: Task<ModelContainer, Error>?
    private var sessions: [UUID: ChatSession] = [:]

    struct LocalModelError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// Downloads (first call only — MLX/Hugging Face's downloader caches it afterwards) and
    /// loads the model into memory. Concurrent callers share the same in-flight work rather
    /// than each kicking off their own download.
    @discardableResult
    func ensureLoaded() async throws -> ModelContainer {
        if let container { return container }
        if let loadTask { return try await loadTask.value }
        status = .working
        let task = Task<ModelContainer, Error> {
            try await #huggingFaceLoadModelContainer(configuration: ModelConfiguration(id: Self.modelID))
        }
        loadTask = task
        do {
            let loaded = try await task.value
            container = loaded
            status = .ready
            loadTask = nil
            return loaded
        } catch {
            status = .failed(error.localizedDescription)
            loadTask = nil
            throw error
        }
    }

    /// Generate a reply for one conversation. `system` only takes effect the first time this
    /// conversation is seen in the current app session, since that's when its ChatSession is
    /// created; later calls reuse that same session so it keeps everything said so far.
    func respond(conversationID: UUID, system: String, userMessage: String) async throws -> String {
        let container = try await ensureLoaded()
        let session: ChatSession
        if let existing = sessions[conversationID] {
            session = existing
        } else {
            session = ChatSession(container, instructions: system,
                                  generateParameters: GenerateParameters(maxTokens: 1024, temperature: 0.7))
            sessions[conversationID] = session
        }
        let reply = try await session.respond(to: userMessage)
        let trimmed = reply.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw LocalModelError(message: "The on-device model returned an empty response.")
        }
        return trimmed
    }

    /// Drop a conversation's in-memory session (e.g. the conversation was deleted) so it's not
    /// held onto for nothing.
    func forget(conversationID: UUID) { sessions.removeValue(forKey: conversationID) }

    /// A one-off response outside any conversation's own session — e.g. generating a short
    /// chat title. Never touches or is remembered by any conversation's own ChatSession.
    func scratchRespond(instructions: String, prompt: String) async throws -> String {
        let container = try await ensureLoaded()
        let session = ChatSession(container, instructions: instructions)
        let reply = try await session.respond(to: prompt)
        let trimmed = reply.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw LocalModelError(message: "The on-device model returned an empty response.")
        }
        return trimmed
    }
}
