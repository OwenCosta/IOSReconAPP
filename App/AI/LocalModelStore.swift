import Foundation
import MLXLLM
import MLXLMCommon
import MLXHuggingFace
import HuggingFace
import Tokenizers

/// Runs a quantised LLM entirely on-device via Apple's MLX framework — no network request, no
/// API key, works fully offline once downloaded. NetTactix offers a catalog of pre-quantised
/// (4-bit) models across a few sizes and purposes, downloaded on demand and cached locally.
///
/// Needs a real Apple-silicon-class iPhone (A-series Neural Engine/GPU via Metal) with enough
/// free storage and RAM — the larger options are genuinely heavier than any of NetTactix's other
/// tools, and all of them are noticeably slower and lower-quality than a cloud API. Offered for
/// when you want the Copilot to work with no network connection and no API key at all.
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

    enum Category: String, CaseIterable {
        case general = "General"
        case coding = "Coding"
        case uncensored = "Uncensored"
    }

    /// One downloadable model. `id` is the exact Hugging Face repo id (also what's stored in
    /// AIProviderConfig.model for a local provider) and what MLX actually downloads/caches by.
    struct ModelOption: Identifiable, Equatable {
        let id: String
        let name: String
        let sizeHint: String
        let summary: String
        let category: Category
    }

    /// All real, verified mlx-community pre-quantised (4-bit) repos — checked against Hugging
    /// Face's own listing (download counts, tags) before inclusion, not guessed at. Sizes are
    /// the standard 4-bit-quantisation estimate for each parameter count (~0.5–0.6 bytes/param
    /// plus tokenizer/config overhead), which matches what Hugging Face reports for the 7B/8B/14B
    /// entries here to within 1%.
    static let catalog: [ModelOption] = [
        ModelOption(id: "mlx-community/Llama-3.2-1B-Instruct-4bit", name: "Llama 3.2 1B", sizeHint: "≈0.7 GB",
                    summary: "Smallest and fastest — lower quality, good for older/storage-constrained iPhones.",
                    category: .general),
        ModelOption(id: "mlx-community/Qwen2.5-1.5B-Instruct-4bit", name: "Qwen2.5 1.5B", sizeHint: "≈0.9 GB",
                    summary: "Small and fast, slightly better reasoning than the 1B option.",
                    category: .general),
        ModelOption(id: "mlx-community/Llama-3.2-3B-Instruct-4bit", name: "Llama 3.2 3B", sizeHint: "≈1.8 GB",
                    summary: "Balanced size/quality for most phones.",
                    category: .general),
        ModelOption(id: "mlx-community/Qwen2.5-7B-Instruct-4bit", name: "Qwen2.5 7B", sizeHint: "≈4.3 GB",
                    summary: "The recommended default — strong general quality for its size.",
                    category: .general),
        ModelOption(id: "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit", name: "Llama 3.1 8B", sizeHint: "≈4.5 GB",
                    summary: "Strong general-purpose alternative to the Qwen 7B default.",
                    category: .general),
        ModelOption(id: "mlx-community/Qwen2.5-14B-Instruct-4bit", name: "Qwen2.5 14B", sizeHint: "≈8.3 GB",
                    summary: "The highest-quality option offered — needs a newer iPhone with plenty of free storage.",
                    category: .general),
        ModelOption(id: "mlx-community/Qwen2.5-Coder-7B-Instruct-4bit", name: "Qwen2.5 Coder 7B", sizeHint: "≈4.3 GB",
                    summary: "Tuned for code — payloads, scripts, parsing exploit output.",
                    category: .coding),
        ModelOption(id: "mlx-community/Meta-Llama-3.1-8B-Instruct-abliterated-4bit", name: "Llama 3.1 8B Abliterated", sizeHint: "≈4.5 GB",
                    summary: "Refusal behaviour removed from the weights — for authorised CTF/red-team content without canned refusals. Same authorised-use terms as the rest of NetTactix apply.",
                    category: .uncensored),
        ModelOption(id: "mlx-community/Qwen2.5-7B-Instruct-Uncensored-4bit", name: "Qwen2.5 7B Uncensored", sizeHint: "≈4.3 GB",
                    summary: "Fine-tuned to drop built-in refusals. Same authorised-use terms as the rest of NetTactix apply.",
                    category: .uncensored),
    ]

    static func option(for id: String) -> ModelOption? { catalog.first { $0.id == id } }

    /// Kept for compatibility with the single-model default — new code should go through the
    /// catalog instead.
    static let modelID = "mlx-community/Qwen2.5-7B-Instruct-4bit"

    @Published private(set) var statuses: [String: Status] = [:]
    private var containers: [String: ModelContainer] = [:]
    private var loadTasks: [String: Task<ModelContainer, Error>] = [:]
    private var sessions: [UUID: ChatSession] = [:]

    struct LocalModelError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    func status(for modelID: String) -> Status { statuses[modelID] ?? .notDownloaded }

    /// Downloads (first call only — MLX/Hugging Face's downloader caches it afterwards) and
    /// loads the given model into memory. Concurrent callers for the same model share the same
    /// in-flight work rather than each kicking off their own download.
    @discardableResult
    func ensureLoaded(modelID: String) async throws -> ModelContainer {
        if let container = containers[modelID] { return container }
        if let existingTask = loadTasks[modelID] { return try await existingTask.value }
        statuses[modelID] = .working
        let task = Task<ModelContainer, Error> {
            try await #huggingFaceLoadModelContainer(configuration: ModelConfiguration(id: modelID))
        }
        loadTasks[modelID] = task
        do {
            let loaded = try await task.value
            containers[modelID] = loaded
            statuses[modelID] = .ready
            loadTasks[modelID] = nil
            return loaded
        } catch {
            statuses[modelID] = .failed(error.localizedDescription)
            loadTasks[modelID] = nil
            throw error
        }
    }

    /// Generate a reply for one conversation on the given model. `system` only takes effect the
    /// first time this conversation is seen in the current app session, since that's when its
    /// ChatSession is created; later calls reuse that same session so it keeps everything said
    /// so far.
    func respond(conversationID: UUID, modelID: String, system: String, userMessage: String) async throws -> String {
        let container = try await ensureLoaded(modelID: modelID)
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
    func scratchRespond(modelID: String, instructions: String, prompt: String) async throws -> String {
        let container = try await ensureLoaded(modelID: modelID)
        let session = ChatSession(container, instructions: instructions)
        let reply = try await session.respond(to: prompt)
        let trimmed = reply.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw LocalModelError(message: "The on-device model returned an empty response.")
        }
        return trimmed
    }
}
