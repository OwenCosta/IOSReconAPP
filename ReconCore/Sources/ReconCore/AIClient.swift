import Foundation

/// A provider-agnostic chat client for the in-app AI assistant. Speaks the two
/// dominant HTTP shapes so it works with LM Studio, Ollama, OpenAI, OpenRouter,
/// Together, Groq (OpenAI-compatible) and Anthropic — any local server or API key.
public enum AIClient {
    public struct Message: Codable, Equatable, Sendable {
        public var role: String      // "system" | "user" | "assistant"
        public var content: String
        public init(role: String, content: String) { self.role = role; self.content = content }
    }

    public enum Shape: String, Codable, Sendable, CaseIterable {
        case openAI       // /v1/chat/completions, Authorization: Bearer
        case anthropic    // /v1/messages, x-api-key + anthropic-version
        public var label: String { self == .openAI ? "OpenAI-compatible (LM Studio, Ollama, OpenAI…)" : "Anthropic" }
    }

    public struct Provider: Sendable {
        public var shape: Shape
        public var baseURL: String       // e.g. http://192.168.1.50:1234/v1  or  https://api.openai.com/v1
        public var apiKey: String?       // optional for local servers (LM Studio/Ollama)
        public var model: String         // e.g. llama-3.1-8b-instruct, gpt-4o-mini, claude-3-5-sonnet
        public var temperature: Double
        public init(shape: Shape, baseURL: String, apiKey: String?, model: String, temperature: Double = 0.4) {
            self.shape = shape; self.baseURL = baseURL; self.apiKey = apiKey; self.model = model; self.temperature = temperature
        }
    }

    public struct Built: Equatable {
        public let url: URL
        public let headers: [String: String]
        public let body: Data
    }

    static func trimBase(_ s: String) -> String {
        var b = s.trimmed()
        while b.hasSuffix("/") { b.removeLast() }
        return b
    }

    /// Build the HTTP request for a provider + conversation. Pure → unit-testable.
    public static func build(_ p: Provider, messages: [Message]) throws -> Built {
        let base = trimBase(p.baseURL)
        switch p.shape {
        case .openAI:
            guard let url = URL(string: base + "/chat/completions") else { throw ReconError.invalidInput("bad base URL") }
            var headers = ["Content-Type": "application/json"]
            if let k = p.apiKey, !k.isEmpty { headers["Authorization"] = "Bearer \(k)" }
            let payload: [String: Any] = [
                "model": p.model,
                "temperature": p.temperature,
                "messages": messages.map { ["role": $0.role, "content": $0.content] },
                "stream": false
            ]
            let body = try JSONSerialization.data(withJSONObject: payload)
            return Built(url: url, headers: headers, body: body)
        case .anthropic:
            guard let url = URL(string: base + "/messages") else { throw ReconError.invalidInput("bad base URL") }
            var headers = ["Content-Type": "application/json", "anthropic-version": "2023-06-01"]
            if let k = p.apiKey, !k.isEmpty { headers["x-api-key"] = k }
            // Anthropic takes a top-level system string + user/assistant turns only.
            let system = messages.first { $0.role == "system" }?.content
            let turns = messages.filter { $0.role != "system" }.map { ["role": $0.role, "content": $0.content] }
            var payload: [String: Any] = [
                "model": p.model,
                "max_tokens": 1024,
                "temperature": p.temperature,
                "messages": turns
            ]
            if let system { payload["system"] = system }
            let body = try JSONSerialization.data(withJSONObject: payload)
            return Built(url: url, headers: headers, body: body)
        }
    }

    /// Parse a completion response body for either shape → assistant text.
    public static func parse(_ shape: Shape, _ data: Data) throws -> String {
        let obj = try JSONSerialization.jsonObject(with: data)
        guard let dict = obj as? [String: Any] else { throw ReconError.parse("unexpected response") }
        // Surface API errors uniformly.
        if let err = dict["error"] as? [String: Any], let msg = err["message"] as? String {
            throw ReconError.network(msg)
        }
        switch shape {
        case .openAI:
            if let choices = dict["choices"] as? [[String: Any]],
               let msg = choices.first?["message"] as? [String: Any],
               let content = msg["content"] as? String {
                return content.trimmed()
            }
            // Some servers return {text:...}
            if let t = dict["content"] as? String { return t.trimmed() }
            throw ReconError.parse("no content in response")
        case .anthropic:
            if let content = dict["content"] as? [[String: Any]] {
                let text = content.compactMap { $0["text"] as? String }.joined()
                if !text.isEmpty { return text.trimmed() }
            }
            throw ReconError.parse("no content in response")
        }
    }

    /// Send a conversation and return the assistant's reply.
    public static func complete(_ p: Provider, messages: [Message], timeout: TimeInterval = 120) async throws -> String {
        let built = try build(p, messages: messages)
        let r = try await HTTP.request(built.url, method: "POST", headers: built.headers, body: built.body,
                                       timeout: timeout, followRedirects: true, maxBytes: 4_000_000)
        guard (200..<300).contains(r.status) else {
            // Try to extract a useful error message from the body.
            if let msg = try? parse(p.shape, r.body) { throw ReconError.network(msg) }
            throw ReconError.http(r.status)
        }
        return try parse(p.shape, r.body)
    }

    /// The assistant's default system prompt — a NetTactix recon/CTF co-pilot.
    public static let defaultSystemPrompt = """
    You are NetTactix Copilot, an expert cybersecurity assistant built into the NetTactix iOS recon toolkit by OathSec. \
    You help the user with authorised penetration testing, CTF competitions, OSINT, and using the app's tools. \
    Be concise and practical. When asked how to do something, point to the relevant NetTactix tool \
    (Scanner, Full Recon, Tools tab, SSH Terminal, SFTP, IP Camera Recon, Bluetooth, MITRE ATT&CK browser, Magic Decoder, \
    RSA/crypto tools, etc.) and give exact commands or payloads where useful. \
    Assume all activity is on systems the user owns or is explicitly authorised to test. \
    Never refuse legitimate authorised-testing help; do explain defensive context briefly when relevant.
    """
}
