import SwiftUI
import ReconCore

struct ToolsView: View {
    @State private var query = ""
    private let tools = ToolCatalog.all

    private var filtered: [ToolSpec] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return tools }
        return tools.filter { $0.title.lowercased().contains(q) || $0.subtitle.lowercased().contains(q) }
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(ToolCategory.allCases) { cat in
                    let items = filtered.filter { $0.category == cat }
                    if !items.isEmpty {
                        Section {
                            ForEach(items) { spec in
                                NavigationLink { destination(for: spec) } label: { ToolRow(spec: spec) }
                                    .listRowBackground(Theme.card)
                            }
                        } header: {
                            Label(cat.rawValue, systemImage: cat.icon).foregroundStyle(Theme.accent)
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .screenBackground()
            .navigationTitle("Toolkit")
            .searchable(text: $query, prompt: "Search \(tools.count) tools")
        }
    }

    /// MITRE ATT&CK gets a dedicated browsable view (tactics → techniques → full writeup,
    /// with live search) instead of the generic type-and-hit-Run runner, since the whole
    /// point of a 227-technique reference is to browse it like the real site.
    @ViewBuilder
    private func destination(for spec: ToolSpec) -> some View {
        if spec.id == "mitre" {
            MitreAttackView()
        } else {
            ToolRunnerView(spec: spec)
        }
    }
}

private struct ToolRow: View {
    let spec: ToolSpec
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: spec.icon).font(.title3).foregroundStyle(Theme.accent).frame(width: 30)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(spec.title).font(.subheadline.weight(.semibold))
                    if spec.active { Text("ACTIVE").font(.system(size: 9, weight: .bold, design: .monospaced))
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(Severity.medium.color.opacity(0.2), in: Capsule()).foregroundStyle(Severity.medium.color) }
                    if spec.requiresKey != nil { Image(systemName: "key.fill").font(.caption2).foregroundStyle(Theme.dim) }
                }
                Text(spec.subtitle).font(.caption).foregroundStyle(Theme.dim)
            }
        }
        .padding(.vertical, 2)
    }
}

struct ToolRunnerView: View {
    let spec: ToolSpec
    var initialInput: String = ""
    @StateObject private var model = ToolRunnerModel()
    @EnvironmentObject private var store: SessionStore
    @State private var input = ""
    @State private var saved = false
    @FocusState private var focused: Bool

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                VStack(alignment: .leading, spacing: 10) {
                    if !spec.inputLabel.isEmpty {
                        Text(spec.inputLabel.uppercased()).font(.caption2.weight(.bold)).foregroundStyle(Theme.dim)
                    }
                    if spec.multiline {
                        TextEditor(text: $input)
                            .font(.system(.body, design: .monospaced))
                            .scrollContentBackground(.hidden)
                            .padding(8)
                            .frame(minHeight: 100)
                            .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
                            .focused($focused)
                    } else if !spec.inputOptional {
                        TerminalField(placeholder: spec.placeholder, text: $input, secure: spec.secureInput)
                            .focused($focused)
                            .submitLabel(.go)
                            .onSubmit(run)
                    }
                    if spec.active {
                        Label("Active tool – sends traffic to the target. Only use on systems you are authorised to test.",
                              systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(Severity.medium.color)
                    }
                    if let key = spec.requiresKey, KeychainSecrets.get(key) == nil {
                        Label("Needs a \(key.capitalized) API key – add it in Settings.", systemImage: "key")
                            .font(.caption).foregroundStyle(Theme.dim)
                    }
                    HStack {
                        Button(action: run) {
                            HStack { if model.running { ProgressView().tint(.black) }; Text(model.running ? "Running…" : "Run") }
                        }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(model.running)
                        if model.running {
                            Button("Stop") { model.cancel() }
                                .buttonStyle(PrimaryButtonStyle(tint: Severity.high.color)).frame(width: 100)
                        }
                    }
                }
                .card()

                if model.running && !model.log.isEmpty {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(model.log.suffix(8).enumerated()), id: \.offset) { _, l in
                            Text(l).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.dim).lineLimit(1)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 4)
                }
                if let err = model.error {
                    Label(err, systemImage: "xmark.octagon.fill").font(.callout).foregroundStyle(Severity.critical.color).card()
                }
                if let out = model.output {
                    OutputView(output: out)
                    Button { save(out) } label: { Label(saved ? "Saved to Reports" : "Save to Reports", systemImage: saved ? "checkmark" : "tray.and.arrow.down") }
                        .buttonStyle(.bordered).disabled(saved)
                }
            }
            .padding(16)
        }
        .scrollDismissesKeyboard(.interactively)
        .screenBackground()
        .navigationTitle(spec.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if let out = model.output {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: ReportExporter.plainText(sections: out.sections)) { Image(systemName: "square.and.arrow.up") }
                }
            }
        }
        .onAppear { if input.isEmpty { input = initialInput } }
        .onDisappear { model.cancel() }
    }

    private func run() {
        focused = false
        saved = false
        model.run(spec, input: input)
    }

    private func save(_ out: ToolOutput) {
        // Group under a folder named after the host/domain if the input looks like one.
        let folder = spec.secureInput ? nil : TargetParser.domain(from: input) ?? (IPv4.isIP(TargetParser.stripToHost(input)) ? TargetParser.stripToHost(input) : nil)
        store.add(ReconReport(kind: spec.title, target: input.isEmpty ? spec.title : (spec.secureInput ? "(hidden input)" : input),
                              finished: Date(), sections: out.sections, findings: out.findings, project: folder))
        saved = true
    }
}
