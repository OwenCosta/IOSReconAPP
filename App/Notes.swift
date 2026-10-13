import SwiftUI
import ReconCore

// MARK: - Model & store

struct FlagNote: Identifiable, Codable, Hashable {
    var id = UUID()
    var title: String
    var body: String
    var solved: Bool = false
    var pinned: Bool = false
    var created: Date = Date()
}

@MainActor
final class NotesStore: ObservableObject {
    @Published private(set) var notes: [FlagNote] = []

    private let url: URL = {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("flagnotes.json")
    }()

    init() { load() }

    var sorted: [FlagNote] {
        notes.sorted {
            if $0.pinned != $1.pinned { return $0.pinned && !$1.pinned }
            if $0.solved != $1.solved { return !$0.solved && $1.solved }
            return $0.created > $1.created
        }
    }
    var solvedCount: Int { notes.filter(\.solved).count }

    func add(_ note: FlagNote) { notes.append(note); save() }
    func update(_ note: FlagNote) {
        if let i = notes.firstIndex(where: { $0.id == note.id }) { notes[i] = note; save() }
    }
    func delete(_ note: FlagNote) { notes.removeAll { $0.id == note.id }; save() }
    func toggleSolved(_ note: FlagNote) { var n = note; n.solved.toggle(); update(n) }
    func togglePinned(_ note: FlagNote) { var n = note; n.pinned.toggle(); update(n) }

    private func load() {
        guard let data = try? Data(contentsOf: url) else { return }
        notes = (try? JSONDecoder().decode([FlagNote].self, from: data)) ?? []
    }
    private func save() {
        if let data = try? JSONEncoder().encode(notes) {
            try? data.write(to: url, options: [.atomic, .completeFileProtection])
        }
    }
}

// MARK: - Views

struct NotesView: View {
    @EnvironmentObject private var store: NotesStore
    @State private var query = ""
    @State private var editing: FlagNote?
    @State private var showingNew = false

    private var filtered: [FlagNote] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return store.sorted }
        return store.sorted.filter { $0.title.lowercased().contains(q) || $0.body.lowercased().contains(q) }
    }

    var body: some View {
        Group {
            if store.notes.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "flag.slash").font(.system(size: 42)).foregroundStyle(Theme.dim)
                    Text("No flags yet").font(.headline)
                    Text("Track challenges and flags here. Everything stays on this device.")
                        .font(.caption).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
                    Button { showingNew = true } label: { Label("Add a challenge", systemImage: "plus") }
                        .buttonStyle(.bordered).padding(.top, 6)
                }.padding(40)
            } else {
                List {
                    ForEach(filtered) { note in
                        Button { editing = note } label: { NoteRow(note: note) }
                            .listRowBackground(Theme.card)
                            .swipeActions(edge: .leading) {
                                Button { store.toggleSolved(note) } label: {
                                    Label(note.solved ? "Unsolve" : "Solved", systemImage: note.solved ? "xmark" : "checkmark")
                                }.tint(Theme.accent)
                            }
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) { store.delete(note) } label: { Label("Delete", systemImage: "trash") }
                                Button { store.togglePinned(note) } label: { Label("Pin", systemImage: "pin") }.tint(Severity.medium.color)
                            }
                    }
                }
                .scrollContentBackground(.hidden)
                .searchable(text: $query, prompt: "Search flags")
            }
        }
        .screenBackground()
        .navigationTitle("Flag Tracker")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { showingNew = true } label: { Image(systemName: "plus") }
            }
        }
        .sheet(item: $editing) { note in
            NoteEditor(note: note) { store.update($0) }
        }
        .sheet(isPresented: $showingNew) {
            NoteEditor(note: FlagNote(title: "", body: "")) { store.add($0) }
        }
    }
}

private struct NoteRow: View {
    let note: FlagNote
    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: note.solved ? "checkmark.seal.fill" : "flag")
                .foregroundStyle(note.solved ? Theme.accent : Theme.dim).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if note.pinned { Image(systemName: "pin.fill").font(.caption2).foregroundStyle(Severity.medium.color) }
                    Text(note.title.isEmpty ? "Untitled" : note.title)
                        .font(.subheadline.weight(.semibold))
                        .strikethrough(note.solved, color: Theme.dim)
                }
                if !note.body.isEmpty {
                    Text(note.body).font(.system(.caption, design: .monospaced)).foregroundStyle(Theme.dim).lineLimit(1)
                }
            }
            Spacer()
        }
        .padding(.vertical, 2)
    }
}

private struct NoteEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var note: FlagNote
    let onSave: (FlagNote) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section("Challenge") {
                    TextField("Name", text: $note.title)
                }
                Section("Flag / notes") {
                    TextEditor(text: $note.body)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 140)
                    if !note.body.isEmpty {
                        Button { UIPasteboard.general.string = note.body } label: { Label("Copy", systemImage: "doc.on.doc") }
                    }
                }
                Section {
                    Toggle("Solved", isOn: $note.solved)
                    Toggle("Pinned", isOn: $note.pinned)
                }
            }
            .navigationTitle(note.title.isEmpty ? "New challenge" : note.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { onSave(note); dismiss() }.disabled(note.title.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
