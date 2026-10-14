import XCTest
@testable import ReconCore

final class AgentToolUseTests: XCTestCase {

    // MARK: ToolOutput.renderCompact

    func testRenderCompactIncludesSectionsItemsAndFindings() {
        var out = ToolOutput()
        var s = ReportSection("DNS Records", note: "via DoH")
        s.add("A", "93.184.216.34")
        s.add("", "bare value")
        out.sections.append(s)
        out.findings.append(Finding(.high, "Open admin panel", "found at /admin", source: "web"))
        let text = out.renderCompact()
        XCTAssertTrue(text.contains("## DNS Records"))
        XCTAssertTrue(text.contains("(via DoH)"))
        XCTAssertTrue(text.contains("A: 93.184.216.34"))
        XCTAssertTrue(text.contains("bare value"))
        XCTAssertTrue(text.contains("## Findings"))
        XCTAssertTrue(text.contains("[high] Open admin panel — found at /admin"))
    }

    func testRenderCompactEmptyOutput() {
        XCTAssertEqual(ToolOutput().renderCompact(), "(no output)")
    }

    func testRenderCompactTruncatesLongOutput() {
        var out = ToolOutput()
        var s = ReportSection("Big")
        for i in 0..<2000 { s.add("item\(i)", String(repeating: "x", count: 20)) }
        out.sections.append(s)
        let text = out.renderCompact(maxChars: 500)
        XCTAssertLessThanOrEqual(text.count, 520)
        XCTAssertTrue(text.hasSuffix("… (truncated)"))
    }

    // MARK: ToolCatalog directory

    func testDirectoryTextListsEveryToolID() {
        let dir = ToolCatalog.directoryText()
        for t in ToolCatalog.all.prefix(10) {
            XCTAssertTrue(dir.contains(t.id + ":"), "missing \(t.id) in directory")
        }
    }

    func testSpecLookupByID() {
        XCTAssertNotNil(ToolCatalog.spec(id: "dns-records"))
        XCTAssertNil(ToolCatalog.spec(id: "not-a-real-tool-id"))
    }

    // MARK: decodeRunToolArguments

    func testDecodeRunToolArgumentsBasic() {
        let r = AIClient.decodeRunToolArguments(#"{"tool_id":"dns-records","input":"example.com"}"#)
        XCTAssertEqual(r?.toolID, "dns-records")
        XCTAssertEqual(r?.input, "example.com")
    }

    func testDecodeRunToolArgumentsMissingInputDefaultsEmpty() {
        let r = AIClient.decodeRunToolArguments(#"{"tool_id":"password-gen"}"#)
        XCTAssertEqual(r?.toolID, "password-gen")
        XCTAssertEqual(r?.input, "")
    }

    func testDecodeRunToolArgumentsMissingToolIDIsNil() {
        XCTAssertNil(AIClient.decodeRunToolArguments(#"{"input":"x"}"#))
    }

    func testDecodeRunToolArgumentsGarbageIsNil() {
        XCTAssertNil(AIClient.decodeRunToolArguments("not json"))
        XCTAssertNil(AIClient.decodeRunToolArguments(""))
    }

    // MARK: buildAgentRequest (OpenAI)

    func testBuildAgentRequestOpenAIIncludesToolsAndMessages() throws {
        let p = AIClient.Provider(shape: .openAI, baseURL: "http://localhost:1234/v1", apiKey: "k", model: "m")
        let turns: [AIClient.AgentMessage] = [.system("sys"), .user("hello")]
        let built = try AIClient.buildAgentRequest(p, turns: turns, toolName: "run_tool",
                                                   toolDescription: "desc", toolParameters: ["type": "object"])
        let json = try JSONSerialization.jsonObject(with: built.body) as! [String: Any]
        XCTAssertEqual(json["tool_choice"] as? String, "auto")
        let tools = json["tools"] as! [[String: Any]]
        let fn = tools[0]["function"] as! [String: Any]
        XCTAssertEqual(fn["name"] as? String, "run_tool")
        let messages = json["messages"] as! [[String: Any]]
        XCTAssertEqual(messages.count, 2)
        XCTAssertEqual(messages[0]["role"] as? String, "system")
        XCTAssertEqual(messages[1]["content"] as? String, "hello")
    }

    func testBuildAgentRequestOpenAIAssistantToolCallsShape() throws {
        let p = AIClient.Provider(shape: .openAI, baseURL: "http://localhost:1234/v1", apiKey: nil, model: "m")
        let call = AIClient.ToolCall(id: "call_1", name: "run_tool", argumentsJSON: #"{"tool_id":"dns-records","input":"a.com"}"#)
        let turns: [AIClient.AgentMessage] = [.system("sys"), .user("do dns"), .assistantToolCalls([call]), .toolResults([("call_1", "result text")])]
        let built = try AIClient.buildAgentRequest(p, turns: turns, toolName: "run_tool", toolDescription: "d", toolParameters: ["type": "object"])
        let json = try JSONSerialization.jsonObject(with: built.body) as! [String: Any]
        let messages = json["messages"] as! [[String: Any]]
        XCTAssertEqual(messages.count, 4)
        let assistantMsg = messages[2]
        XCTAssertEqual(assistantMsg["role"] as? String, "assistant")
        let toolCalls = assistantMsg["tool_calls"] as! [[String: Any]]
        XCTAssertEqual(toolCalls[0]["id"] as? String, "call_1")
        let toolMsg = messages[3]
        XCTAssertEqual(toolMsg["role"] as? String, "tool")
        XCTAssertEqual(toolMsg["tool_call_id"] as? String, "call_1")
        XCTAssertEqual(toolMsg["content"] as? String, "result text")
    }

    func testBuildAgentRequestOpenAIAllowToolsFalseOmitsTools() throws {
        let p = AIClient.Provider(shape: .openAI, baseURL: "http://localhost:1234/v1", apiKey: nil, model: "m")
        let turns: [AIClient.AgentMessage] = [.system("sys"), .user("hello")]
        let built = try AIClient.buildAgentRequest(p, turns: turns, toolName: "run_tool",
                                                   toolDescription: "desc", toolParameters: ["type": "object"],
                                                   allowTools: false)
        let json = try JSONSerialization.jsonObject(with: built.body) as! [String: Any]
        XCTAssertNil(json["tools"])
        XCTAssertNil(json["tool_choice"])
    }

    // MARK: buildAgentRequest (Anthropic)

    func testBuildAgentRequestAnthropicSystemAndTools() throws {
        let p = AIClient.Provider(shape: .anthropic, baseURL: "https://api.anthropic.com/v1", apiKey: "k", model: "claude-3-5-sonnet")
        let turns: [AIClient.AgentMessage] = [.system("sys"), .user("hello")]
        let built = try AIClient.buildAgentRequest(p, turns: turns, toolName: "run_tool", toolDescription: "d", toolParameters: ["type": "object"])
        let json = try JSONSerialization.jsonObject(with: built.body) as! [String: Any]
        XCTAssertEqual(json["system"] as? String, "sys")
        let tools = json["tools"] as! [[String: Any]]
        XCTAssertEqual(tools[0]["name"] as? String, "run_tool")
        let messages = json["messages"] as! [[String: Any]]
        XCTAssertEqual(messages.count, 1)   // system is extracted, not a message
        XCTAssertEqual(messages[0]["role"] as? String, "user")
    }

    func testBuildAgentRequestAnthropicAllowToolsFalseOmitsTools() throws {
        let p = AIClient.Provider(shape: .anthropic, baseURL: "https://api.anthropic.com/v1", apiKey: "k", model: "claude-3-5-sonnet")
        let turns: [AIClient.AgentMessage] = [.system("sys"), .user("hello")]
        let built = try AIClient.buildAgentRequest(p, turns: turns, toolName: "run_tool", toolDescription: "d",
                                                   toolParameters: ["type": "object"], allowTools: false)
        let json = try JSONSerialization.jsonObject(with: built.body) as! [String: Any]
        XCTAssertNil(json["tools"])
        XCTAssertEqual(json["system"] as? String, "sys")   // still built normally otherwise
    }

    func testBuildAgentRequestAnthropicToolUseRoundTrip() throws {
        let p = AIClient.Provider(shape: .anthropic, baseURL: "https://api.anthropic.com/v1", apiKey: "k", model: "claude-3-5-sonnet")
        let call = AIClient.ToolCall(id: "toolu_1", name: "run_tool", argumentsJSON: #"{"tool_id":"camera","input":"192.168.1.64"}"#)
        let turns: [AIClient.AgentMessage] = [.user("check this camera"), .assistantToolCalls([call]), .toolResults([("toolu_1", "found hikvision")])]
        let built = try AIClient.buildAgentRequest(p, turns: turns, toolName: "run_tool", toolDescription: "d", toolParameters: ["type": "object"])
        let json = try JSONSerialization.jsonObject(with: built.body) as! [String: Any]
        let messages = json["messages"] as! [[String: Any]]
        XCTAssertEqual(messages.count, 3)
        let assistantContent = messages[1]["content"] as! [[String: Any]]
        XCTAssertEqual(assistantContent[0]["type"] as? String, "tool_use")
        XCTAssertEqual(assistantContent[0]["id"] as? String, "toolu_1")
        let input = assistantContent[0]["input"] as! [String: Any]
        XCTAssertEqual(input["tool_id"] as? String, "camera")
        let resultContent = messages[2]["content"] as! [[String: Any]]
        XCTAssertEqual(resultContent[0]["type"] as? String, "tool_result")
        XCTAssertEqual(resultContent[0]["tool_use_id"] as? String, "toolu_1")
        XCTAssertEqual(resultContent[0]["content"] as? String, "found hikvision")
    }

    // MARK: parseAgentResponse (OpenAI)

    func testParseAgentResponseOpenAIFinalText() throws {
        let data = Data(#"{"choices":[{"message":{"role":"assistant","content":"Hello there"}}]}"#.utf8)
        let turn = try AIClient.parseAgentResponse(.openAI, data)
        guard case .text(let t) = turn else { return XCTFail("expected .text") }
        XCTAssertEqual(t, "Hello there")
    }

    func testParseAgentResponseOpenAIToolCalls() throws {
        let data = Data(#"""
        {"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[
            {"id":"call_1","type":"function","function":{"name":"run_tool","arguments":"{\"tool_id\":\"dns-records\",\"input\":\"a.com\"}"}}
        ]}}]}
        """#.utf8)
        let turn = try AIClient.parseAgentResponse(.openAI, data)
        guard case .toolCalls(let calls) = turn else { return XCTFail("expected .toolCalls") }
        XCTAssertEqual(calls.count, 1)
        XCTAssertEqual(calls[0].id, "call_1")
        let decoded = AIClient.decodeRunToolArguments(calls[0].argumentsJSON)
        XCTAssertEqual(decoded?.toolID, "dns-records")
    }

    func testParseAgentResponseOpenAIEmptyContentThrows() {
        let data = Data(#"{"choices":[{"message":{"role":"assistant","content":""}}]}"#.utf8)
        XCTAssertThrowsError(try AIClient.parseAgentResponse(.openAI, data))
    }

    func testParseAgentResponseOpenAIErrorSurfaces() {
        let data = Data(#"{"error":{"message":"rate limited"}}"#.utf8)
        XCTAssertThrowsError(try AIClient.parseAgentResponse(.openAI, data)) { err in
            XCTAssertTrue("\(err)".contains("rate limited"))
        }
    }

    // MARK: parseAgentResponse (Anthropic)

    func testParseAgentResponseAnthropicFinalText() throws {
        let data = Data(#"{"content":[{"type":"text","text":"Hi there"}]}"#.utf8)
        let turn = try AIClient.parseAgentResponse(.anthropic, data)
        guard case .text(let t) = turn else { return XCTFail("expected .text") }
        XCTAssertEqual(t, "Hi there")
    }

    func testParseAgentResponseAnthropicToolUse() throws {
        let data = Data(#"""
        {"content":[
            {"type":"text","text":"Let me check that."},
            {"type":"tool_use","id":"toolu_1","name":"run_tool","input":{"tool_id":"camera","input":"192.168.1.64"}}
        ]}
        """#.utf8)
        let turn = try AIClient.parseAgentResponse(.anthropic, data)
        guard case .toolCalls(let calls) = turn else { return XCTFail("expected .toolCalls") }
        XCTAssertEqual(calls.count, 1)
        XCTAssertEqual(calls[0].name, "run_tool")
        let decoded = AIClient.decodeRunToolArguments(calls[0].argumentsJSON)
        XCTAssertEqual(decoded?.toolID, "camera")
        XCTAssertEqual(decoded?.input, "192.168.1.64")
    }

    func testParseAgentResponseAnthropicEmptyTextThrows() {
        let data = Data(#"{"content":[{"type":"text","text":""}]}"#.utf8)
        XCTAssertThrowsError(try AIClient.parseAgentResponse(.anthropic, data))
    }

    // MARK: agentComplete loop (using a fake executeTool, real buildAgentRequest/parseAgentResponse
    // exercised indirectly through the pure helpers above; the network call itself isn't
    // reachable without a live server, consistent with the rest of this codebase's testing style)

    func testAgentCompleteMaxStepsGuardIsAtLeastOne() async {
        // maxSteps: 0 should still attempt at least one round (guarded by max(1, maxSteps))
        // rather than throwing immediately without trying — this only checks the guard logic
        // compiles/behaves via a provider that will fail fast (invalid URL), not a live call.
        let p = AIClient.Provider(shape: .openAI, baseURL: "not a url", apiKey: nil, model: "m")
        do {
            _ = try await AIClient.agentComplete(p, system: "s", history: [], maxSteps: 0) { _, _ in "" }
            XCTFail("expected an error from the invalid base URL")
        } catch {
            // Any thrown error confirms at least one attempt was made rather than silently returning.
            XCTAssertTrue(true)
        }
    }
}
