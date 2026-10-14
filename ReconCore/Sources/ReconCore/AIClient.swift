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
    ///
    /// Two things that otherwise produce a silent blank reply, now handled:
    /// 1. A final SSE line with no trailing newline (the connection just closes after it) —
    ///    flushed from the buffer on completion instead of being dropped.
    /// 2. A server that ignores `stream: true` and sends one ordinary (non-SSE) JSON body —
    ///    if no deltas were parsed, the raw body is retried through the normal non-streaming
    ///    parser before giving up.
    private final class StreamDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
        private let shape: Shape
        private let onDelta: @Sendable (String) -> Void
        var finish: (@Sendable (Result<String, Error>) -> Void)?
        private let lock = NSLock()
        private var buffer = Data()           // undrained bytes, newline-delimited
        private var rawBody = Data()          // everything received, for the non-SSE fallback
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
            rawBody.append(data)
            buffer.append(data)
            lock.unlock()
            drainLines(includingTrailingPartial: false)
        }

        /// Pulls complete `\n`-terminated lines out of `buffer` and forwards any delta each
        /// one carries. With `includingTrailingPartial: true` (end-of-stream only), also
        /// consumes a final line that never got its trailing newline.
        private func drainLines(includingTrailingPartial: Bool) {
            while true {
                lock.lock()
                let lineData: Data
                if let nl = buffer.firstIndex(of: 0x0A) {
                    lineData = buffer.subdata(in: buffer.startIndex..<nl)
                    buffer.removeSubrange(buffer.startIndex...nl)
                } else if includingTrailingPartial, !buffer.isEmpty {
                    lineData = buffer
                    buffer.removeAll()
                } else {
                    lock.unlock(); break
                }
                lock.unlock()
                guard let line = String(data: lineData, encoding: .utf8),
                      let payload = AIClient.ssePayload(fromLine: line),
                      let delta = AIClient.parseSSEDelta(shape, payload: payload) else { continue }
                lock.lock(); fullText += delta; lock.unlock()
                onDelta(delta)
            }
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
            if error == nil { drainLines(includingTrailingPartial: true) }
            lock.lock()
            let text = fullText, code = statusCode, isErr = isErrorResponse
            let errData = errorBuffer, body = rawBody
            let already = resolved; resolved = true
            lock.unlock()
            guard !already else { return }
            if let error { finish?(.failure(ReconError.network(error.localizedDescription))); return }
            if isErr {
                if let msg = try? AIClient.parse(shape, errData) { finish?(.failure(ReconError.network(msg))) }
                else { finish?(.failure(ReconError.http(code))) }
                return
            }
            if !text.isEmpty { finish?(.success(text)); return }
            // No SSE deltas parsed — maybe the server ignored stream:true and sent a plain
            // (non-streamed) completion body instead. Try that before giving up.
            if !body.isEmpty, let fallback = try? AIClient.parse(shape, body), !fallback.isEmpty {
                onDelta(fallback)
                finish?(.success(fallback))
                return
            }
            if body.isEmpty { finish?(.failure(ReconError.network("empty response from server"))) }
            else { finish?(.failure(ReconError.parse("model returned an empty response"))) }
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

    // MARK: - Tool use ("function calling")

    /// One function call the model asked to make.
    public struct ToolCall: Sendable, Equatable {
        public let id: String
        public let name: String
        public let argumentsJSON: String
    }

    /// What one agent request/response round-trip produced.
    public enum AgentTurn: Sendable, Equatable {
        case text(String)
        case toolCalls([ToolCall])
    }

    /// A turn in the wire conversation for a tool-enabled request. Distinct from the plain
    /// `Message` because assistant tool-call turns and tool-result turns don't fit a flat
    /// role+content pair on either provider's wire format.
    enum AgentMessage: Sendable {
        case system(String)
        case user(String)
        case assistantText(String)
        case assistantToolCalls([ToolCall])
        case toolResults([(callID: String, text: String)])
    }

    /// The single generic function exposed to the model: call any NetTactix tool by id.
    /// One function (rather than one per catalog entry) keeps the request small and works
    /// reliably even with smaller/local models — the full catalog is listed in the system
    /// prompt instead (see `ToolCatalog.directoryText()`).
    public static let runToolName = "run_tool"
    public static let runToolDescription =
        "Run one NetTactix tool by its id and return its output. Pick tool_id from the tool directory given in the system prompt."
    public static let runToolParameters: [String: Any] = [
        "type": "object",
        "properties": [
            "tool_id": ["type": "string", "description": "The exact tool id from the directory, e.g. \"dns-records\"."],
            "input": ["type": "string", "description": "The target/text to pass to the tool. Empty string if the tool takes no input."]
        ],
        "required": ["tool_id"]
    ]

    /// Build the HTTP request for one agent turn. Pure → unit-testable. When `allowTools` is
    /// false, the request omits the tool/tool_choice fields entirely so the model is physically
    /// unable to request another tool call — used to force a plain-text final answer.
    static func buildAgentRequest(_ p: Provider, turns: [AgentMessage],
                                  toolName: String, toolDescription: String, toolParameters: [String: Any],
                                  allowTools: Bool = true) throws -> Built {
        let base = trimBase(p.baseURL)
        switch p.shape {
        case .openAI:
            guard let url = URL(string: base + "/chat/completions") else { throw ReconError.invalidInput("bad base URL") }
            var headers = ["Content-Type": "application/json"]
            if let k = p.apiKey, !k.isEmpty { headers["Authorization"] = "Bearer \(k)" }
            var wire: [[String: Any]] = []
            for t in turns {
                switch t {
                case .system(let s): wire.append(["role": "system", "content": s])
                case .user(let s): wire.append(["role": "user", "content": s])
                case .assistantText(let s): wire.append(["role": "assistant", "content": s])
                case .assistantToolCalls(let calls):
                    wire.append([
                        "role": "assistant", "content": NSNull(),
                        "tool_calls": calls.map { c in
                            ["id": c.id, "type": "function", "function": ["name": c.name, "arguments": c.argumentsJSON]]
                        }
                    ])
                case .toolResults(let results):
                    for r in results { wire.append(["role": "tool", "tool_call_id": r.callID, "content": r.text]) }
                }
            }
            var payload: [String: Any] = [
                "model": p.model, "temperature": p.temperature, "messages": wire, "stream": false
            ]
            if allowTools {
                payload["tools"] = [["type": "function", "function": ["name": toolName, "description": toolDescription, "parameters": toolParameters]]]
                payload["tool_choice"] = "auto"
            }
            return Built(url: url, headers: headers, body: try JSONSerialization.data(withJSONObject: payload))
        case .anthropic:
            guard let url = URL(string: base + "/messages") else { throw ReconError.invalidInput("bad base URL") }
            var headers = ["Content-Type": "application/json", "anthropic-version": "2023-06-01"]
            if let k = p.apiKey, !k.isEmpty { headers["x-api-key"] = k }
            var system = ""
            var wire: [[String: Any]] = []
            for t in turns {
                switch t {
                case .system(let s): system += (system.isEmpty ? "" : "\n") + s
                case .user(let s): wire.append(["role": "user", "content": s])
                case .assistantText(let s): wire.append(["role": "assistant", "content": s])
                case .assistantToolCalls(let calls):
                    let blocks: [[String: Any]] = calls.map { c in
                        let input = (try? JSONSerialization.jsonObject(with: Data(c.argumentsJSON.utf8))) as? [String: Any] ?? [:]
                        return ["type": "tool_use", "id": c.id, "name": c.name, "input": input]
                    }
                    wire.append(["role": "assistant", "content": blocks])
                case .toolResults(let results):
                    let blocks: [[String: Any]] = results.map { ["type": "tool_result", "tool_use_id": $0.callID, "content": $0.text] }
                    wire.append(["role": "user", "content": blocks])
                }
            }
            var payload: [String: Any] = [
                "model": p.model, "max_tokens": 1024, "temperature": p.temperature, "messages": wire, "stream": false
            ]
            if allowTools {
                payload["tools"] = [["name": toolName, "description": toolDescription, "input_schema": toolParameters]]
            }
            if !system.isEmpty { payload["system"] = system }
            return Built(url: url, headers: headers, body: try JSONSerialization.data(withJSONObject: payload))
        }
    }

    /// Parse one agent response: either the final text, or the tool call(s) the model wants
    /// to make. Pure → unit-testable.
    static func parseAgentResponse(_ shape: Shape, _ data: Data) throws -> AgentTurn {
        let obj = try JSONSerialization.jsonObject(with: data)
        guard let dict = obj as? [String: Any] else { throw ReconError.parse("unexpected response") }
        if let err = dict["error"] as? [String: Any], let msg = err["message"] as? String { throw ReconError.network(msg) }
        switch shape {
        case .openAI:
            guard let choices = dict["choices"] as? [[String: Any]], let message = choices.first?["message"] as? [String: Any] else {
                throw ReconError.parse("no content in response")
            }
            if let rawCalls = message["tool_calls"] as? [[String: Any]], !rawCalls.isEmpty {
                let calls: [ToolCall] = rawCalls.compactMap { c in
                    guard let id = c["id"] as? String, let fn = c["function"] as? [String: Any],
                          let name = fn["name"] as? String, let args = fn["arguments"] as? String else { return nil }
                    return ToolCall(id: id, name: name, argumentsJSON: args)
                }
                if !calls.isEmpty { return .toolCalls(calls) }
            }
            guard let content = message["content"] as? String, !content.trimmed().isEmpty else {
                throw ReconError.parse("model returned an empty response")
            }
            return .text(content.trimmed())
        case .anthropic:
            guard let content = dict["content"] as? [[String: Any]] else { throw ReconError.parse("no content in response") }
            var calls: [ToolCall] = []
            var text = ""
            for block in content {
                guard let type = block["type"] as? String else { continue }
                if type == "tool_use", let id = block["id"] as? String, let name = block["name"] as? String {
                    let input = block["input"] as? [String: Any] ?? [:]
                    let argsData = (try? JSONSerialization.data(withJSONObject: input)) ?? Data("{}".utf8)
                    calls.append(ToolCall(id: id, name: name, argumentsJSON: String(data: argsData, encoding: .utf8) ?? "{}"))
                } else if type == "text", let t = block["text"] as? String {
                    text += t
                }
            }
            if !calls.isEmpty { return .toolCalls(calls) }
            guard !text.trimmed().isEmpty else { throw ReconError.parse("model returned an empty response") }
            return .text(text.trimmed())
        }
    }

    /// Decode the generic `run_tool` function's arguments. Pure → unit-testable.
    public static func decodeRunToolArguments(_ json: String) -> (toolID: String, input: String)? {
        guard let data = json.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let toolID = obj["tool_id"] as? String, !toolID.isEmpty else { return nil }
        return (toolID, (obj["input"] as? String) ?? "")
    }

    /// Run a tool-enabled conversation to completion: the model may call `run_tool` any
    /// number of times (bounded by `maxSteps`); each call is executed via `executeTool` and
    /// fed back, until the model produces a final text reply. On the last allowed step the
    /// request is sent with tools disabled, so the model is physically unable to call another
    /// tool and must answer in plain text — this guarantees the loop always terminates with a
    /// real reply instead of erroring out. Each HTTP round-trip is individually bounded by
    /// `timeout`, so a single slow request can't hang the whole conversation either. Returns
    /// the final reply plus a log of which tools were called, for display. Not streamed — a
    /// tool-calling turn resolves in one block rather than token-by-token.
    public static func agentComplete(_ p: Provider, system: String, history: [Message],
                                     maxSteps: Int = 6, timeout: TimeInterval = 180,
                                     executeTool: @escaping @Sendable (_ toolID: String, _ input: String) async -> String
                                     ) async throws -> (text: String, toolLog: [(toolID: String, input: String)]) {
        var turns: [AgentMessage] = [.system(system)]
        for m in history {
            if m.role == "user" { turns.append(.user(m.content)) }
            else if m.role == "assistant" { turns.append(.assistantText(m.content)) }
        }
        var toolLog: [(toolID: String, input: String)] = []
        let stepCount = max(1, maxSteps)
        for step in 0..<stepCount {
            let isLastStep = step == stepCount - 1
            let built = try buildAgentRequest(p, turns: turns, toolName: runToolName,
                                              toolDescription: runToolDescription, toolParameters: runToolParameters,
                                              allowTools: !isLastStep)
            let r = try await HTTP.request(built.url, method: "POST", headers: built.headers, body: built.body,
                                           timeout: timeout, followRedirects: true, maxBytes: 4_000_000)
            guard (200..<300).contains(r.status) else {
                if let msg = try? parse(p.shape, r.body) { throw ReconError.network(msg) }
                throw ReconError.http(r.status)
            }
            switch try parseAgentResponse(p.shape, r.body) {
            case .text(let text):
                return (text, toolLog)
            case .toolCalls(let calls):
                // Tools were disallowed on the forced-final step, so a provider that still
                // returns a tool call here is non-compliant — fall back gracefully rather
                // than ever throwing a dead-end error back at the user.
                if isLastStep {
                    return ("I wasn't able to finish that within the allowed steps — try asking again, or something more specific.", toolLog)
                }
                turns.append(.assistantToolCalls(calls))
                var results: [(callID: String, text: String)] = []
                for c in calls {
                    guard let (toolID, input) = decodeRunToolArguments(c.argumentsJSON) else {
                        results.append((c.id, "error: could not parse the tool call's arguments"))
                        continue
                    }
                    toolLog.append((toolID, input))
                    results.append((c.id, await executeTool(toolID, input)))
                }
                turns.append(.toolResults(results))
            }
        }
        return ("I wasn't able to finish that within the allowed steps — try asking again, or something more specific.", toolLog)
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
