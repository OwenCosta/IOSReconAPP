import XCTest
@testable import ReconCore

final class AdvancedFeatureTests: XCTestCase {

    // MARK: MITRE ATT&CK

    func testMitreCoversAllTactics() {
        for ta in MitreAttack.tactics {
            XCTAssertFalse(MitreAttack.techniques(in: ta.id).isEmpty, "\(ta.id) \(ta.name) has no techniques")
        }
        XCTAssertEqual(MitreAttack.tactics.count, 14)
        XCTAssertGreaterThanOrEqual(MitreAttack.techniques.count, 50)
    }

    func testMitreLookupById() {
        XCTAssertEqual(MitreAttack.technique("T1059")?.name, "Command and Scripting Interpreter")
        XCTAssertEqual(MitreAttack.technique("t1059")?.name, "Command and Scripting Interpreter")  // case-insensitive
        XCTAssertEqual(MitreAttack.tactic("TA0006")?.name, "Credential Access")
    }

    func testMitreSearch() {
        let hits = MitreAttack.search("phishing")
        XCTAssertTrue(hits.contains { $0.id == "T1566" })
        let brute = MitreAttack.search("brute")
        XCTAssertTrue(brute.contains { $0.id == "T1110" })
    }

    func testMitreRunRoutes() {
        // technique detail
        let detail = MitreAttack.run("T1486")
        XCTAssertTrue(detail.sections.first?.title.contains("Ransomware") == false) // title is id+name
        XCTAssertTrue(detail.sections.first?.title.contains("T1486") == true)
        // tactic listing
        let tactic = MitreAttack.run("TA0002")
        XCTAssertTrue((tactic.sections.first?.items.count ?? 0) >= 3)
        // overview
        let overview = MitreAttack.run("")
        XCTAssertEqual(overview.sections.first?.items.count, 14)
    }

    func testMitreUniqueIDs() {
        let ids = MitreAttack.techniques.map(\.id)
        XCTAssertEqual(Set(ids).count, ids.count, "duplicate technique ids")
    }

    // MARK: AI client

    func testBuildOpenAIRequest() throws {
        let p = AIClient.Provider(shape: .openAI, baseURL: "http://192.168.1.50:1234/v1/", apiKey: "localkey", model: "llama-3.1-8b")
        let built = try AIClient.build(p, messages: [.init(role: "user", content: "hi")])
        XCTAssertEqual(built.url.absoluteString, "http://192.168.1.50:1234/v1/chat/completions")  // trailing slash trimmed
        XCTAssertEqual(built.headers["Authorization"], "Bearer localkey")
        let json = try JSONSerialization.jsonObject(with: built.body) as! [String: Any]
        XCTAssertEqual(json["model"] as? String, "llama-3.1-8b")
        XCTAssertEqual(json["stream"] as? Bool, false)
        XCTAssertEqual((json["messages"] as? [[String: Any]])?.count, 1)
    }

    func testBuildOpenAINoKeyOmitsAuth() throws {
        let p = AIClient.Provider(shape: .openAI, baseURL: "http://localhost:1234/v1", apiKey: nil, model: "m")
        let built = try AIClient.build(p, messages: [.init(role: "user", content: "x")])
        XCTAssertNil(built.headers["Authorization"])
    }

    func testBuildAnthropicSplitsSystem() throws {
        let p = AIClient.Provider(shape: .anthropic, baseURL: "https://api.anthropic.com/v1", apiKey: "k", model: "claude-3-5-sonnet")
        let msgs: [AIClient.Message] = [.init(role: "system", content: "be helpful"), .init(role: "user", content: "hi")]
        let built = try AIClient.build(p, messages: msgs)
        XCTAssertEqual(built.url.absoluteString, "https://api.anthropic.com/v1/messages")
        XCTAssertEqual(built.headers["x-api-key"], "k")
        XCTAssertEqual(built.headers["anthropic-version"], "2023-06-01")
        let json = try JSONSerialization.jsonObject(with: built.body) as! [String: Any]
        XCTAssertEqual(json["system"] as? String, "be helpful")
        XCTAssertEqual((json["messages"] as? [[String: Any]])?.count, 1)  // system removed from messages
    }

    func testParseOpenAIResponse() throws {
        let data = Data(#"{"choices":[{"message":{"role":"assistant","content":" hello there "}}]}"#.utf8)
        XCTAssertEqual(try AIClient.parse(.openAI, data), "hello there")
    }

    func testParseAnthropicResponse() throws {
        let data = Data(#"{"content":[{"type":"text","text":"hi"},{"type":"text","text":" world"}]}"#.utf8)
        XCTAssertEqual(try AIClient.parse(.anthropic, data), "hi world")
    }

    func testParseErrorSurfacesMessage() {
        let data = Data(#"{"error":{"message":"invalid api key"}}"#.utf8)
        XCTAssertThrowsError(try AIClient.parse(.openAI, data)) { err in
            XCTAssertTrue("\(err)".contains("invalid api key"))
        }
    }

    // MARK: Streaming (SSE)

    func testBuildWithStreamTrueSetsFlagBothShapes() throws {
        let openAI = AIClient.Provider(shape: .openAI, baseURL: "http://localhost:1234/v1", apiKey: nil, model: "m")
        let openAIBuilt = try AIClient.build(openAI, messages: [.init(role: "user", content: "hi")], stream: true)
        let openAIJSON = try JSONSerialization.jsonObject(with: openAIBuilt.body) as! [String: Any]
        XCTAssertEqual(openAIJSON["stream"] as? Bool, true)

        let anthropic = AIClient.Provider(shape: .anthropic, baseURL: "https://api.anthropic.com/v1", apiKey: "k", model: "claude-3-5-sonnet")
        let anthropicBuilt = try AIClient.build(anthropic, messages: [.init(role: "user", content: "hi")], stream: true)
        let anthropicJSON = try JSONSerialization.jsonObject(with: anthropicBuilt.body) as! [String: Any]
        XCTAssertEqual(anthropicJSON["stream"] as? Bool, true)
    }

    func testBuildDefaultsStreamFalse() throws {
        let p = AIClient.Provider(shape: .openAI, baseURL: "http://localhost:1234/v1", apiKey: nil, model: "m")
        let built = try AIClient.build(p, messages: [.init(role: "user", content: "hi")])
        let json = try JSONSerialization.jsonObject(with: built.body) as! [String: Any]
        XCTAssertEqual(json["stream"] as? Bool, false)
    }

    func testSSEPayloadStripsDataPrefix() {
        XCTAssertEqual(AIClient.ssePayload(fromLine: "data: hello"), "hello")
        XCTAssertEqual(AIClient.ssePayload(fromLine: "data:hello"), "hello")
        XCTAssertEqual(AIClient.ssePayload(fromLine: "data:   {\"a\":1}  "), "{\"a\":1}")
    }

    func testSSEPayloadIgnoresNonDataLines() {
        XCTAssertNil(AIClient.ssePayload(fromLine: "event: message_start"))
        XCTAssertNil(AIClient.ssePayload(fromLine: ": this is a comment"))
        XCTAssertNil(AIClient.ssePayload(fromLine: ""))
        XCTAssertNil(AIClient.ssePayload(fromLine: "id: 123"))
    }

    func testParseSSEDeltaOpenAIChunk() {
        let payload = #"{"id":"x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hel"},"finish_reason":null}]}"#
        XCTAssertEqual(AIClient.parseSSEDelta(.openAI, payload: payload), "Hel")
    }

    func testParseSSEDeltaOpenAIDoneSentinelIsNil() {
        XCTAssertNil(AIClient.parseSSEDelta(.openAI, payload: "[DONE]"))
    }

    func testParseSSEDeltaOpenAIRoleOnlyChunkIsNil() {
        // The first chunk of a stream often carries only {"role":"assistant"} with no content yet.
        let payload = #"{"choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#
        XCTAssertNil(AIClient.parseSSEDelta(.openAI, payload: payload))
    }

    func testParseSSEDeltaOpenAIFinishChunkIsNil() {
        let payload = #"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#
        XCTAssertNil(AIClient.parseSSEDelta(.openAI, payload: payload))
    }

    func testParseSSEDeltaAnthropicTextDelta() {
        let payload = #"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}}"#
        XCTAssertEqual(AIClient.parseSSEDelta(.anthropic, payload: payload), "Hel")
    }

    func testParseSSEDeltaAnthropicNonTextEventsAreNil() {
        XCTAssertNil(AIClient.parseSSEDelta(.anthropic, payload: #"{"type":"message_start","message":{"id":"msg_1"}}"#))
        XCTAssertNil(AIClient.parseSSEDelta(.anthropic, payload: #"{"type":"ping"}"#))
        XCTAssertNil(AIClient.parseSSEDelta(.anthropic, payload: #"{"type":"content_block_stop","index":0}"#))
        XCTAssertNil(AIClient.parseSSEDelta(.anthropic, payload: #"{"type":"message_stop"}"#))
    }

    func testParseSSEDeltaGarbageIsNil() {
        XCTAssertNil(AIClient.parseSSEDelta(.openAI, payload: "not json at all"))
        XCTAssertNil(AIClient.parseSSEDelta(.openAI, payload: ""))
    }

    func testParseSSEDeltaAssemblesFullReplyAcrossChunks() {
        let chunks = [
            #"{"choices":[{"delta":{"role":"assistant"}}]}"#,
            #"{"choices":[{"delta":{"content":"Hel"}}]}"#,
            #"{"choices":[{"delta":{"content":"lo "}}]}"#,
            #"{"choices":[{"delta":{"content":"world"}}]}"#,
            "[DONE]"
        ]
        let full = chunks.compactMap { AIClient.parseSSEDelta(.openAI, payload: $0) }.joined()
        XCTAssertEqual(full, "Hello world")
    }
}
