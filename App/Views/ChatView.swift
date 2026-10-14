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
                    if sending {
                        HStack(spacing: 6) { ProgressView().controlSize(.small); Text("thinking…").font(.caption).foregroundStyle(Theme.dim) }
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Color.clear.frame(height: 1).id("bottom")
                }.padding(14)
            }
            .onChange(of: convo.messages.count) { _ in withAnimation { proxy.scrollTo("bottom", anchor: .bottom) } }
            .onChange(of: sending) { _ in withAnimation { proxy.scrollTo("bottom", anchor: .bottom) } }
        }
    }

    private var visibleMessages: [AIConversation.Msg] { convo.messages.filter { $0.role != "system" } }

    private func bubble(_ m: AIConversation.Msg) -> some View {
        let isUser = m.role == "user"
        return HStack {
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

        let runtime = ai.runtime(p)
        var wire: [AIClient.Message] = [.init(role: "system", content: AIClient.defaultSystemPrompt)]
        wire += convo.messages.filter { $0.role != "system" }.map { .init(role: $0.role, content: $0.content) }

        Task {
            do {
                let reply = try await AIClient.complete(runtime, messages: wire)
                convo.messages.append(.init(role: "assistant", content: reply))
                ai.update(convo)
            } catch {
                errorText = (error as? ReconError)?.errorDescription ?? "\(error)"
            }
            sending = false
        }
    }
}
