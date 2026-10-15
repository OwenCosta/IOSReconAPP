import SwiftUI
import ReconCore

struct LearnView: View {
    @State private var query = ""

    private var sections: [LearnSection] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return LearnContent.sections }
        return LearnContent.sections.compactMap { sec in
            let hits = sec.entries.filter { $0.term.lowercased().contains(q) || $0.definition.lowercased().contains(q) }
            return hits.isEmpty ? nil : LearnSection(sec.title, icon: sec.icon, hits)
        }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    if query.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("The field guide").font(.headline).foregroundStyle(Theme.accent)
                            Text("Plain-language explanations of the concepts behind every tool: \(LearnContent.termCount) terms across \(LearnContent.sections.count) topics. Search or browse.")
                                .font(.callout).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .card()
                    }
                    ForEach(sections) { section in
                        LearnSectionCard(section: section, expanded: !query.isEmpty)
                    }
                    if sections.isEmpty {
                        Text("No terms match “\(query)”.").font(.callout).foregroundStyle(Theme.dim).padding(.top, 30)
                    }
                }
                .padding(16)
            }
            .scrollDismissesKeyboard(.interactively)
            .screenBackground()
            .navigationTitle("Learn")
            .searchable(text: $query, prompt: "Search terms")
        }
    }
}

private struct LearnSectionCard: View {
    let section: LearnSection
    let expanded: Bool
    @State private var open: Set<UUID> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: section.icon).foregroundStyle(Theme.accent)
                Text(section.title).font(.headline).foregroundStyle(Theme.accent)
                Spacer()
                Text("\(section.entries.count)").font(.caption).foregroundStyle(Theme.dim)
            }
            ForEach(section.entries) { entry in
                let isOpen = expanded || open.contains(entry.id)
                VStack(alignment: .leading, spacing: 4) {
                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) {
                            if open.contains(entry.id) { open.remove(entry.id) } else { open.insert(entry.id) }
                        }
                    } label: {
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: isOpen ? "minus.circle" : "plus.circle")
                                .font(.caption).foregroundStyle(Theme.dim).padding(.top, 2)
                            Text(entry.term).font(.subheadline.weight(.semibold)).foregroundStyle(Theme.fg)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .buttonStyle(.plain)
                    if isOpen {
                        Text(entry.definition)
                            .font(.callout).foregroundStyle(Theme.dim)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                            .padding(.leading, 22)
                    }
                }
                if entry.id != section.entries.last?.id { Divider().overlay(Theme.stroke) }
            }
        }
        .card()
    }
}
