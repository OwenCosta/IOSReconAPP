import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

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
    /// `stream: true` asks the provider for a server-sent-events response (see `streamComplete`).
    public static func build(_ p: Provider, messages: [Message], stream: Bool = false) throws -> Built {
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
                "stream": stream
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
                "messages": turns,
                "stream": stream
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

    // MARK: - Streaming (server-sent events)

    /// Extract the incremental text from one decoded SSE "data:" payload, or nil if the
    /// event carries no text (pings, message-start/stop, `[DONE]`, …). Pure → unit-testable.
    public static func parseSSEDelta(_ shape: Shape, payload: String) -> String? {
        let trimmed = payload.trimmed()
        guard !trimmed.isEmpty, trimmed != "[DONE]" else { return nil }
        guard let data = trimmed.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        switch shape {
        case .openAI:
            guard let choices = obj["choices"] as? [[String: Any]],
                  let delta = choices.first?["delta"] as? [String: Any],
                  let content = delta["content"] as? String, !content.isEmpty else { return nil }
            return content
        case .anthropic:
            guard obj["type"] as? String == "content_block_delta",
                  let delta = obj["delta"] as? [String: Any],
                  delta["type"] as? String == "text_delta",
                  let text = delta["text"] as? String, !text.isEmpty else { return nil }
            return text
        }
    }

    /// Split a raw "data: ..." SSE line into its payload (the part after the prefix).
    static func ssePayload(fromLine line: String) -> String? {
        let t = line.trimmed()
        guard t.hasPrefix("data:") else { return nil }
        return String(t.dropFirst(5)).trimmed()
    }

    /// Accumulates a streamed HTTP response, splitting it on newlines into SSE events and
    /// forwarding each one's text delta — byte-safe (only decodes once a full line has
    /// arrived, so multi-byte UTF-8 never splits across network chunks).
    private final class StreamDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
        private let shape: Shape
        private let onDelta: @Sendable (String) -> Void
        var finish: (@Sendable (Result<String, Error>) -> Void)?
        private let lock = NSLock()
        private var buffer = Data()
        private var fullText = ""
        private var statusCode = 200
        private var isErrorResponse = false
        private var errorBuffer = Data()
        private var resolved = false

        init(shape: Shape, onDelta: @escaping @Sendable (String) -> Void) {
            self.shape = shape; self.onDelta = onDelta
        }

        func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
            if let http = response as? HTTPURLResponse {
                lock.lock(); statusCode = http.statusCode; isErrorResponse = !(200..<300).contains(http.statusCode); lock.unlock()
            }
            completionHandler(.allow)
        }

        func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
            lock.lock()
            if isErrorResponse { errorBuffer.append(data); lock.unlock(); return }
            buffer.append(data)
            lock.unlock()
            drainLines()
        }

        private func drainLines() {
            while true {
                lock.lock()
                guard let nl = buffer.firstIndex(of: 0x0A) else { lock.unlock(); break }
                let lineData = buffer.subdata(in: buffer.startIndex..<nl)
                buffer.removeSubrange(buffer.startIndex...nl)
                lock.unlock()
                guard let line = String(data: lineData, encoding: .utf8),
                      let payload = AIClient.ssePayload(fromLine: line),
                      let delta = AIClient.parseSSEDelta(shape, payload: payload) else { continue }
                lock.lock(); fullText += delta; lock.unlock()
                onDelta(delta)
            }
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
            lock.lock()
            let text = fullText, code = statusCode, isErr = isErrorResponse, errData = errorBuffer
            let already = resolved; resolved = true
            lock.unlock()
            guard !already else { return }
            if let error { finish?(.failure(ReconError.network(error.localizedDescription))); return }
            if isErr {
                if let msg = try? AIClient.parse(shape, errData) { finish?(.failure(ReconError.network(msg))) }
                else { finish?(.failure(ReconError.http(code))) }
                return
            }
            finish?(.success(text))
        }
    }

    /// Stream a chat completion, invoking `onDelta` with each incremental text fragment as
    /// it arrives (token-by-token where the provider supports it — all of LM Studio, Ollama,
    /// OpenAI, OpenRouter and Anthropic do), and returning the full assembled reply once the
    /// stream ends. `onDelta` is called off the main thread; hop back explicitly if updating UI.
    public static func streamComplete(_ p: Provider, messages: [Message], timeout: TimeInterval = 120,
                                      onDelta: @escaping @Sendable (String) -> Void) async throws -> String {
        let built = try build(p, messages: messages, stream: true)
        var req = URLRequest(url: built.url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: timeout)
        req.httpMethod = "POST"
        req.httpBody = built.body
        req.setValue(HTTP.userAgent, forHTTPHeaderField: "User-Agent")
        for (k, v) in built.headers { req.setValue(v, forHTTPHeaderField: k) }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout * 2
        let delegate = StreamDelegate(shape: p.shape, onDelta: onDelta)
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        return try await withCheckedThrowingContinuation { cont in
            delegate.finish = { result in
                switch result {
                case .success(let text): cont.resume(returning: text)
                case .failure(let error): cont.resume(throwing: error)
                }
            }
            session.dataTask(with: req).resume()
        }
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
