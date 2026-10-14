import SwiftUI
import ReconCore

/// A single AI conversation: message history, input, and send-to-model.
struct ChatView: View {
    @EnvironmentObject private var ai: AIStore
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
                Text("No AI provider selected. Add one from Copilot → ⋯ → AI providers.")
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

    private func send() {
        guard let p = provider else { return }
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        input = ""
        errorText = nil
        if convo.title == "New chat" { convo.title = String(text.prefix(40)) }
        convo.messages.append(.init(role: "user", content: text))
        ai.update(convo)
        sending = true

        if ai.toolsAllowed {
            sendWithTools(p)
        } else {
            sendStreaming(p)
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

        Task {
            do {
                _ = try await AIClient.streamComplete(runtime, messages: wire) { delta in
                    Task { @MainActor in
                        guard let i = convo.messages.firstIndex(where: { $0.id == assistantID }) else { return }
                        convo.messages[i].content += delta
                    }
                }
            } catch {
                convo.messages.removeAll { $0.id == assistantID && $0.content.isEmpty }
                errorText = (error as? ReconError)?.errorDescription ?? "\(error)"
            }
            ai.update(convo)
            sending = false
        }
    }

    /// Tool-enabled path: the model may call NetTactix tools (bounded, logged visibly as
    /// "🔧" bubbles) before giving its final answer. Resolves in one block rather than
    /// streaming token-by-token, since the model may pause mid-turn to call a tool.
    private func sendWithTools(_ p: AIProviderConfig) {
        let runtime = ai.runtime(p)
        let system = AIClient.defaultSystemPrompt + """


        You have permission to use NetTactix's own tools via the run_tool function. \
        Available tools (id: title — subtitle [input]):
        \(ToolCatalog.directoryText())

        Call run_tool with the exact tool_id and the right input whenever it would help answer \
        the user. You may call more than one tool across turns. Give your final answer as plain text.
        """
        let history = convo.messages.dropLast().filter { $0.role == "user" || $0.role == "assistant" }
            .map { AIClient.Message(role: $0.role, content: $0.content) }

        Task {
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
            } catch {
                errorText = (error as? ReconError)?.errorDescription ?? "\(error)"
            }
            ai.update(convo)
            sending = false
        }
    }
}
