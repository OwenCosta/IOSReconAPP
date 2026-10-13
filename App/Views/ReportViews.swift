import SwiftUI
import ReconCore

struct ItemRow: View {
    let item: ReportItem
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Circle().fill(item.severity.color).frame(width: 7, height: 7).padding(.top, 5)
            if !item.label.isEmpty {
                Text(item.label)
                    .font(Theme.mono)
                    .foregroundStyle(Theme.dim)
                    .frame(width: 118, alignment: .leading)
            }
            Text(item.value)
                .font(Theme.mono)
                .foregroundStyle(item.severity >= .medium ? item.severity.color : Color.white)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .contextMenu {
            Button { UIPasteboard.general.string = item.value } label: { Label("Copy value", systemImage: "doc.on.doc") }
            if !item.label.isEmpty {
                Button { UIPasteboard.general.string = "\(item.label): \(item.value)" } label: { Label("Copy line", systemImage: "text.alignleft") }
            }
        }
    }
}

struct SectionCard: View {
    let section: ReportSection
    @State private var collapsed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { collapsed.toggle() }
            } label: {
                HStack {
                    Text(section.title).font(.headline).foregroundStyle(Theme.accent).multilineTextAlignment(.leading)
                    Spacer()
                    Image(systemName: collapsed ? "chevron.down" : "chevron.up").font(.caption).foregroundStyle(Theme.dim)
                }
            }
            .buttonStyle(.plain)

            if !collapsed {
                if let n = section.note { Text(n).font(.caption).foregroundStyle(Theme.dim) }
                LazyVStack(alignment: .leading, spacing: 7) {
                    ForEach(section.items) { ItemRow(item: $0) }
                }
            }
        }
        .card()
    }
}

struct FindingsCard: View {
    let findings: [Finding]
    var body: some View {
        let sorted = findings.sorted { $0.severity > $1.severity }
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Findings (\(findings.count))").font(.headline).foregroundStyle(Theme.accent)
                Spacer()
                ForEach(Severity.allCases.reversed().filter { $0 != .info }, id: \.self) { sev in
                    let n = findings.filter { $0.severity == sev }.count
                    if n > 0 { Text("\(n)").font(.caption.bold()).padding(.horizontal, 7).padding(.vertical, 2)
                        .background(sev.color.opacity(0.2), in: Capsule()).foregroundStyle(sev.color) }
                }
            }
            ForEach(sorted) { f in
                VStack(alignment: .leading, spacing: 3) {
                    HStack(alignment: .top) {
                        SeverityChip(severity: f.severity)
                        Text(f.title).font(.subheadline.weight(.semibold)).fixedSize(horizontal: false, vertical: true)
                    }
                    if !f.detail.isEmpty {
                        Text(f.detail).font(.caption).foregroundStyle(Theme.dim).textSelection(.enabled)
                    }
                }
                .contextMenu {
                    Button { UIPasteboard.general.string = f.title + (f.detail.isEmpty ? "" : "\n\(f.detail)") } label: { Label("Copy", systemImage: "doc.on.doc") }
                }
                if f.id != sorted.last?.id { Divider().overlay(Theme.stroke) }
            }
        }
        .card()
    }
}

/// Renders findings + all sections of a tool result.
struct OutputView: View {
    let output: ToolOutput
    var body: some View {
        LazyVStack(spacing: 12) {
            if !output.findings.isEmpty { FindingsCard(findings: output.findings) }
            ForEach(output.sections) { SectionCard(section: $0) }
        }
    }
}

struct ReportDetailView: View {
    let report: ReconReport
    var body: some View {
        ScrollView {
            OutputView(output: ToolOutput(sections: report.sections, findings: report.findings))
                .padding(16)
        }
        .screenBackground()
        .navigationTitle(report.target)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    ShareLink(item: ReportExporter.markdown(report)) { Label("Share Markdown", systemImage: "doc.richtext") }
                    if let data = ReportExporter.json(report), let s = String(data: data, encoding: .utf8) {
                        ShareLink(item: s) { Label("Share JSON", systemImage: "curlybraces") }
                    }
                } label: { Image(systemName: "square.and.arrow.up") }
            }
        }
    }
}

struct ReportRow: View {
    let report: ReconReport
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon).foregroundStyle(report.worstSeverity.color).frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(report.target).font(.system(.body, design: .monospaced)).lineLimit(1)
                Text("\(report.kind) · \(report.started.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption).foregroundStyle(Theme.dim)
            }
            Spacer()
            if !report.findings.isEmpty { SeverityChip(severity: report.worstSeverity) }
        }
    }
    private var icon: String {
        switch report.kind {
        case "Full Recon": return "scope"
        case "Port Scan": return "dot.radiowaves.left.and.right"
        default: return "doc.text"
        }
    }
}
