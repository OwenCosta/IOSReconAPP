import SwiftUI
import ReconCore

/// A browsable MITRE ATT&CK Enterprise matrix — tactics you drill into, techniques you tap
/// for the full writeup, and a live search across all 227 — instead of the generic
/// type-something-and-hit-Run tool pattern. The closest a phone screen gets to actually
/// browsing attack.mitre.org.
struct MitreAttackView: View {
    @State private var query = ""

    private var searching: Bool { !query.trimmingCharacters(in: .whitespaces).isEmpty }
    private var hits: [MitreAttack.Technique] { MitreAttack.search(query) }

    var body: some View {
        List {
            if searching {
                Section {
                    if hits.isEmpty {
                        Text("No matches for \u{201c}\(query)\u{201d}").font(.caption).foregroundStyle(Theme.dim)
                    } else {
                        ForEach(hits) { t in
                            NavigationLink { MitreTechniqueView(technique: t) } label: { MitreTechniqueRow(technique: t) }
                                .listRowBackground(Theme.card)
                        }
                    }
                } header: { Text("\(hits.count) matches") }
            } else {
                Section {
                    Text("MITRE ATT&CK — Enterprise matrix. \(MitreAttack.techniques.count) techniques across \(MitreAttack.tactics.count) tactics, offline.")
                        .font(.caption).foregroundStyle(Theme.dim)
                } .listRowBackground(Color.clear)
                ForEach(MitreAttack.tactics) { ta in
                    Section {
                        NavigationLink { MitreTacticView(tactic: ta) } label: { MitreTacticRow(tactic: ta) }
                            .listRowBackground(Theme.card)
                    }
                }
            }
        }
        .scrollContentBackground(.hidden)
        .screenBackground()
        .navigationTitle("MITRE ATT&CK")
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $query, prompt: "Search all \(MitreAttack.techniques.count) techniques")
    }
}

private struct MitreTacticRow: View {
    let tactic: MitreAttack.Tactic
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(tactic.id).font(.caption2.monospaced()).foregroundStyle(Theme.accent)
                    Text(tactic.name).font(.subheadline.weight(.semibold)).foregroundStyle(Theme.fg)
                }
                Text(tactic.summary).font(.caption).foregroundStyle(Theme.dim).lineLimit(2)
            }
            Spacer()
            Text("\(MitreAttack.techniques(in: tactic.id).count)").font(.caption.monospaced()).foregroundStyle(Theme.dim)
            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(Theme.dim)
        }
    }
}

private struct MitreTechniqueRow: View {
    let technique: MitreAttack.Technique
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(technique.id).font(.caption2.monospaced()).foregroundStyle(Theme.accent)
                Text(technique.name).font(.subheadline.weight(.semibold)).foregroundStyle(Theme.fg).lineLimit(1)
            }
            Text(technique.summary).font(.caption).foregroundStyle(Theme.dim).lineLimit(2)
        }
    }
}

/// One tactic's technique list — the "column" of the real matrix.
private struct MitreTacticView: View {
    let tactic: MitreAttack.Tactic
    private var techniques: [MitreAttack.Technique] { MitreAttack.techniques(in: tactic.id) }

    var body: some View {
        List {
            Section {
                Text(tactic.summary).font(.caption).foregroundStyle(Theme.dim)
            }.listRowBackground(Color.clear)
            Section {
                ForEach(techniques) { t in
                    NavigationLink { MitreTechniqueView(technique: t) } label: { MitreTechniqueRow(technique: t) }
                        .listRowBackground(Theme.card)
                }
            } header: { Text("\(techniques.count) techniques") }
        }
        .scrollContentBackground(.hidden)
        .screenBackground()
        .navigationTitle(tactic.name)
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// One technique's full writeup — what the "Run" report used to squeeze into a text blob.
private struct MitreTechniqueView: View {
    let technique: MitreAttack.Technique
    @EnvironmentObject private var store: SessionStore
    @State private var saved = false

    private var referenceURL: URL? {
        URL(string: "https://attack.mitre.org/techniques/\(technique.id.replacingOccurrences(of: ".", with: "/"))/")
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(technique.id).font(.caption.monospaced()).foregroundStyle(Theme.accent)
                    Text(technique.name).font(.title3.weight(.bold)).foregroundStyle(Theme.fg)
                    HStack(spacing: 6) {
                        ForEach(technique.tactics, id: \.self) { taID in
                            if let ta = MitreAttack.tactic(taID) {
                                NavigationLink { MitreTacticView(tactic: ta) } label: {
                                    Text(ta.name).font(.caption2.weight(.semibold))
                                        .padding(.horizontal, 8).padding(.vertical, 3)
                                        .background(Theme.accent.opacity(0.15), in: Capsule())
                                        .foregroundStyle(Theme.accent)
                                }
                            }
                        }
                    }
                }.card()

                detailBlock("What it is", technique.summary)
                detailBlock("Detect", technique.detection)
                detailBlock("Mitigate", technique.mitigation)

                if let url = referenceURL {
                    Link(destination: url) {
                        HStack { Image(systemName: "safari"); Text("View on attack.mitre.org") }
                    }
                    .buttonStyle(.bordered)
                }

                Button { save() } label: {
                    Label(saved ? "Saved to Reports" : "Save to Reports", systemImage: saved ? "checkmark" : "tray.and.arrow.down")
                }
                .buttonStyle(.bordered).disabled(saved)
            }
            .padding(16)
        }
        .screenBackground()
        .navigationTitle(technique.id)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if let url = referenceURL {
                ToolbarItem(placement: .topBarTrailing) { ShareLink(item: url) { Image(systemName: "square.and.arrow.up") } }
            }
        }
    }

    private func detailBlock(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased()).font(.caption2.weight(.bold)).foregroundStyle(Theme.dim)
            Text(body).font(.callout).foregroundStyle(Theme.fg)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }

    private func save() {
        var s = ReportSection("\(technique.id) — \(technique.name)",
                              note: "Tactic: \(technique.tactics.compactMap { MitreAttack.tactic($0)?.name }.joined(separator: ", "))")
        s.add("What", technique.summary)
        s.add("Detect", technique.detection, .low)
        s.add("Mitigate", technique.mitigation, .low)
        if let url = referenceURL { s.add("Reference", url.absoluteString) }
        store.add(ReconReport(kind: "MITRE ATT&CK", target: technique.id, finished: Date(), sections: [s], findings: [], project: nil))
        saved = true
    }
}
