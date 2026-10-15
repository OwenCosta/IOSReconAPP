import SwiftUI
import ReconCore

/// A single AI conversation: message history, input, and send-to-model.
struct ChatView: View {
    @EnvironmentObject private var ai: AIStore
    @EnvironmentObject private var localModel: LocalModelStore
    @State private var convo: AIConversation
    @State private var input = ""
    @State private var sending = false
    @State private var errorText: String?
    @FocusState private var inputFocused: Bool

    init(conversation: AIConversation) { _convo = State(initialValue: conversation) }

    private var provider: AIProviderConfig? {
        ai.providers.first { $0.id == convo.providerID } ?? ai.selectedProvider
    }

    var body: some View {
        VStack(spacing: 0) {
            if provider == nil {
                Text("No AI provider selected. Add one from Assistant → ⋯ → AI providers.")
                    .font(.caption).foregroundStyle(Theme.dim).padding()
            }
            messages
            if let e = errorText {
                Text(e).font(.caption).foregroundStyle(Severity.high.color)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 14).padding(.vertical, 6)
                    .background(Theme.card)
            }
            inputBar
        }
        .screenBackground()
        .navigationTitle(convo.title).navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if let p = provider { Text(p.model).font(.caption2).foregroundStyle(Theme.dim) }
            }
        }
        .onAppear(perform: cleanUpOrphanedPlaceholder)
    }

    private var messages: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(visibleMessages) { m in bubble(m) }
                    if showThinking {
                        HStack(spacing: 6) { ProgressView().controlSize(.small); Text("thinking…").font(.caption).foregroundStyle(Theme.dim) }
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Color.clear.frame(height: 1).id("bottom")
                }.padding(14)
            }
            .onChange(of: convo.messages.count) { _ in withAnimation { proxy.scrollTo("bottom", anchor: .bottom) } }
            .onChange(of: sending) { _ in withAnimation { proxy.scrollTo("bottom", anchor: .bottom) } }
            .onChange(of: convo.messages.last?.content) { _ in proxy.scrollTo("bottom", anchor: .bottom) }
        }
    }

    /// Empty-content messages (the assistant placeholder before its first streamed token
    /// arrives) are hidden — "thinking…" covers that gap instead of an empty bubble.
    private var visibleMessages: [AIConversation.Msg] { convo.messages.filter { $0.role != "system" && !$0.content.isEmpty } }

    /// True whenever a request is in flight and nothing has fully answered yet. Keeps
    /// showing through tool-call bubbles (role "tool") since those are progress, not the
    /// final reply — only an empty or absent assistant message (or none at all) means "wait".
    private var showThinking: Bool {
        guard sending, let last = convo.messages.last else { return sending }
        if last.role == "assistant" { return last.content.isEmpty }
        return true
    }

    private func bubble(_ m: AIConversation.Msg) -> some View {
        if m.role == "tool" {
            return AnyView(
                HStack(spacing: 6) {
                    Image(systemName: "wrench.and.screwdriver.fill").font(.caption2)
                    Text(m.content).font(.system(.caption2, design: .monospaced)).lineLimit(2)
                    Spacer()
                }
                .foregroundStyle(Theme.accent)
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(Theme.accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            )
        }
        let isUser = m.role == "user"
        return AnyView(
            HStack {
                if isUser { Spacer(minLength: 40) }
                Text(m.content)
                    .font(.callout)
                    .foregroundStyle(isUser ? Color.black : Theme.fg)
                    .textSelection(.enabled)
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    .background(isUser ? Theme.accent : Theme.card,
                                in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .frame(maxWidth: .infinity, alignment: isUser ? .trailing : .leading)
                if !isUser { Spacer(minLength: 40) }
            }
        )
    }

    private var inputBar: some View {
        HStack(spacing: 8) {
            TextField("Ask your recon copilot…", text: $input, axis: .vertical)
                .lineLimit(1...5)
                .textInputAutocapitalization(.sentences)
                .focused($inputFocused)
                .padding(10)
                .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
            Button(action: send) {
                Image(systemName: "arrow.up.circle.fill").font(.title2)
                    .foregroundStyle(canSend ? Theme.accent : Theme.dim)
            }
            .buttonStyle(.plain).disabled(!canSend)
        }
        .padding(10).background(Theme.card)
    }

    private var canSend: Bool {
        !sending && provider != nil && !input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Requests extra execution time from iOS for an in-flight reply so briefly backgrounding
    /// the app (switching to check something else, a notification, the app sliding to the
    /// background for a moment) doesn't get the request killed mid-flight. This is a real but
    /// bounded grace period (iOS still suspends the app after its own limit, typically well
    /// under a minute) — not indefinite background operation, which iOS doesn't allow for an
    /// ordinary foreground app without a push-driven or background-upload architecture.
    private func withBackgroundTime(_ body: @escaping () async -> Void) {
        var taskID: UIBackgroundTaskIdentifier = .invalid
        taskID = UIApplication.shared.beginBackgroundTask(withName: "nettactix.ai.reply") {
            UIApplication.shared.endBackgroundTask(taskID)
            taskID = .invalid
        }
        Task {
            await body()
            if taskID != .invalid {
                UIApplication.shared.endBackgroundTask(taskID)
                taskID = .invalid
            }
        }
    }

    /// Clears out an empty assistant placeholder left behind by a reply that never finished
    /// (e.g. the app was force-quit mid-stream) — otherwise it sits invisibly in storage
    /// forever (visibleMessages hides empty content) and, worse, silently confuses future
    /// history if ever un-hidden. Safe to call any time nothing is actively sending, since a
    /// genuinely in-progress placeholder only exists while `sending` is true in this same view.
    private func cleanUpOrphanedPlaceholder() {
        guard !sending else { return }
        let before = convo.messages.count
        convo.messages.removeAll { $0.role == "assistant" && $0.content.isEmpty }
        if convo.messages.count != before { ai.update(convo) }
    }

    /// After the first exchange, ask the model for a short, descriptive title instead of
    /// settling for the raw truncated first message. Fire-and-forget: if the extra request
    /// fails, times out, or the provider doesn't like it, the chat just keeps the placeholder
    /// title set in `send()` — never blocks sending or surfaces an error of its own.
    private func maybeGenerateTitle(_ p: AIProviderConfig) {
        guard convo.messages.filter({ $0.role == "user" }).count == 1,
              let firstUser = convo.messages.first(where: { $0.role == "user" })?.content,
              !firstUser.isEmpty else { return }
        let prompt = """
        Reply with ONLY a short title (3-6 words, no quotes, no trailing punctuation) summarising \
        this chat for a conversation list:

        \(firstUser.prefix(300))
        """
        let instructions = "You write short chat titles only, no extra commentary."
        if p.isLocalModel {
            Task { @MainActor in
                guard let raw = try? await localModel.scratchRespond(modelID: p.model, instructions: instructions, prompt: prompt) else { return }
                applyGeneratedTitle(raw)
            }
        } else {
            let runtime = ai.runtime(p)
            Task { @MainActor in
                guard let raw = try? await AIClient.complete(runtime, messages: [
                    .init(role: "system", content: instructions),
                    .init(role: "user", content: prompt)
                ], timeout: 30) else { return }
                applyGeneratedTitle(raw)
            }
        }
    }

    private func applyGeneratedTitle(_ raw: String) {
        let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'“”.!"))
        guard !cleaned.isEmpty, cleaned.count <= 80 else { return }
        convo.title = cleaned
        ai.update(convo)
    }

    private func send() {
        guard let p = provider else { return }
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        inputFocused = false   // commit/dismiss any in-progress autocorrect candidate first,
        input = ""             // so clearing the field can't be reverted by the text system
        errorText = nil
        if convo.title == "New chat" { convo.title = String(text.prefix(40)) }
        convo.messages.append(.init(role: "user", content: text))
        ai.update(convo)
        sending = true

        // The on-device model never goes through AIClient/HTTP, but it does get real tool
        // calling via MLX's own ChatSession tool support (see LocalModelStore.respond) — same
        // toolsAllowed/small-talk gating as the remote path below, just a different mechanism.
        if p.isLocalModel {
            sendLocal(p, allowTools: ai.toolsAllowed && !isSmallTalk(text))
            return
        }

        // Small talk never goes through the tool-calling API at all — not just a prompt
        // without the catalog, but the OpenAI/Anthropic request body itself omits the
        // tools/tool_choice fields (agentComplete always sets those when allowTools is true,
        // regardless of what the system prompt says). Many local models get confused or
        // return empty content the moment a "tools" field is present, independent of wording,
        // so a plain greeting goes through exactly the same path as tools-off.
        if ai.toolsAllowed && !isSmallTalk(text) {
            sendWithTools(p)
        } else {
            sendStreaming(p)
        }
    }

    /// On-device (MLX) path: no HTTP request, but real tool calling when `allowTools` is true
    /// (see LocalModelStore.respond) — resolves in one block like sendWithTools rather than
    /// streaming token-by-token, since the model may pause mid-turn to call a tool.
    private func sendLocal(_ p: AIProviderConfig, allowTools: Bool) {
        let conversationID = convo.id
        let lastUser = convo.messages.last(where: { $0.role == "user" })?.content ?? ""
        // Same directory text the remote tool-calling path uses, only included when tools are
        // actually in play — keeps the system prompt short (and small/local models from
        // free-associating on tool names) the rest of the time, same reasoning as sendWithTools.
        let system = allowTools ? AIClient.defaultSystemPrompt + """


            Tools: call run_tool only when this message actually needs one: a scan, lookup, \
            decode/convert/generate, or another result only a tool can produce. Otherwise answer \
            directly in plain text; most messages need no tool. Directory (id: title, subtitle):
            \(ToolCatalog.directoryText())

            Important: after a tool runs, the user does NOT see its output. Only a small \
            "Ran: <tool name>" line with no results. You are the only one who sees what the \
            tool actually returned, so your final answer must state the real findings yourself \
            (the actual values, numbers, addresses, names, whatever the tool returned), in full. \
            Never say things like "see above", "as shown above", or "the results are displayed": \
            nothing is displayed except what you write.
            """ : AIClient.defaultSystemPrompt
        withBackgroundTime {
            do {
                let reply = try await localModel.respond(
                    conversationID: conversationID, modelID: p.model, system: system, userMessage: lastUser,
                    allowTools: allowTools,
                    onToolCall: { id, input in
                        Task { @MainActor in
                            let label = ToolCatalog.spec(id: id)?.title ?? id
                            let shown = input.isEmpty ? label : "\(label)(\(input.prefix(60)))"
                            convo.messages.append(.init(role: "tool", content: "Ran: \(shown)"))
                            ai.update(convo)
                        }
                    }
                )
                convo.messages.append(.init(role: "assistant", content: reply))
                maybeGenerateTitle(p)
            } catch {
                errorText = (error as? LocalizedError)?.errorDescription ?? "\(error)"
            }
            ai.update(convo)
            sending = false
        }
    }

    /// Default path: plain token-by-token streaming, no tool use.
    private func sendStreaming(_ p: AIProviderConfig) {
        // An empty placeholder the stream fills in token-by-token; hidden from view until
        // its first delta lands (see `visibleMessages` / `showThinking`).
        let assistantID = UUID()
        convo.messages.append(.init(id: assistantID, role: "assistant", content: ""))
        ai.update(convo)

        let runtime = ai.runtime(p)
        var wire: [AIClient.Message] = [.init(role: "system", content: AIClient.defaultSystemPrompt)]
        wire += convo.messages.dropLast().filter { $0.role != "system" && $0.role != "tool" }.map { .init(role: $0.role, content: $0.content) }

        withBackgroundTime {
            do {
                _ = try await AIClient.streamComplete(runtime, messages: wire) { delta in
                    Task { @MainActor in
                        guard let i = convo.messages.firstIndex(where: { $0.id == assistantID }) else { return }
                        convo.messages[i].content += delta
                    }
                }
                maybeGenerateTitle(p)
            } catch {
                convo.messages.removeAll { $0.id == assistantID && $0.content.isEmpty }
                errorText = (error as? ReconError)?.errorDescription ?? "\(error)"
            }
            ai.update(convo)
            sending = false
        }
    }

    /// Exact (not just short) greetings/chit-chat that never need a tool. A real request can be
    /// short too ("scan 10.0.0.1", "T1059"), so this only matches an explicit, unambiguous
    /// allowlist rather than any brief message. Messages that match skip the tool-calling API
    /// entirely (see `send()`) and go through plain streaming instead, same as tools-off.
    private static let smallTalk: Set<String> = [
        "hi", "hii", "hiya", "hello", "hey", "yo", "sup", "wassup", "what's up", "whats up",
        "good morning", "good afternoon", "good evening", "good night",
        "thanks", "thank you", "thx", "ty", "ok", "okay", "cool", "nice", "lol", "haha",
        "how are you", "how's it going", "hows it going", "who are you", "what can you do", "test"
    ]
    private func isSmallTalk(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: .punctuationCharacters)
            .lowercased()
        return Self.smallTalk.contains(t)
    }

    /// Tool-enabled path: the model may call NetTactix tools (bounded, logged visibly as
    /// "🔧" bubbles) before giving its final answer. Resolves in one block rather than
    /// streaming token-by-token, since the model may pause mid-turn to call a tool. `send()`
    /// never routes small talk here — anything that does reach this function genuinely could
    /// use a tool, so the full catalog and tool-calling API are always in play.
    private func sendWithTools(_ p: AIProviderConfig) {
        let runtime = ai.runtime(p)
        let system = AIClient.defaultSystemPrompt + """


            Tools: call run_tool only when this message actually needs one: a scan, lookup, \
            decode/convert/generate, or another result only a tool can produce. Otherwise answer \
            directly in plain text; most messages need no tool. Directory (id: title, subtitle):
            \(ToolCatalog.directoryText())

            Important: after a tool runs, the user does NOT see its output. Only a small \
            "Ran: <tool name>" line with no results. You are the only one who sees what the \
            tool actually returned, so your final answer must state the real findings yourself \
            (the actual values, numbers, addresses, names, whatever the tool returned), in full. \
            Never say things like "see above", "as shown above", or "the results are displayed": \
            nothing is displayed except what you write.
            """
        // No trailing placeholder is appended in this path (unlike sendStreaming), so the
        // current user message is already the last element — do NOT dropLast() here, or the
        // model never sees what was actually just asked and answers an empty conversation.
        let history = convo.messages.filter { $0.role == "user" || $0.role == "assistant" }
            .map { AIClient.Message(role: $0.role, content: $0.content) }

        withBackgroundTime {
            do {
                let (finalText, _) = try await AIClient.agentComplete(runtime, system: system, history: history) { id, toolInput in
                    let label = ToolCatalog.spec(id: id)?.title ?? id
                    let result = await AIStore.executeTool(id: id, input: toolInput)
                    await MainActor.run {
                        let shown = toolInput.isEmpty ? label : "\(label)(\(toolInput.prefix(60)))"
                        convo.messages.append(.init(role: "tool", content: "Ran: \(shown)"))
                    }
                    return result
                }
                convo.messages.append(.init(role: "assistant", content: finalText))
                maybeGenerateTitle(p)
            } catch {
                errorText = (error as? ReconError)?.errorDescription ?? "\(error)"
            }
            ai.update(convo)
            sending = false
        }
    }
}
