import SwiftUI
import ReconCore

@MainActor
final class FullReconModel: ObservableObject {
    @Published var target = ""
    @Published var options = FullReconOptions()
    @Published var running = false
    @Published var stage = ""
    @Published var fraction = 0.0
    @Published var log: [String] = []
    @Published var sections: [ReportSection] = []
    @Published var findings: [Finding] = []
    @Published var report: ReconReport?
    /// Set only by a user-initiated stop() — lets the view mark whatever sections/findings
    /// accumulated so far as incomplete, instead of looking like a normal finished run just
    /// because results are present.
    @Published var stoppedEarly = false
    private var task: Task<Void, Never>?

    func start(store: SessionStore) {
        guard !running else { return }
        running = true
        stoppedEarly = false
        stage = "Starting…"
        fraction = 0
        log = []
        sections = []
        findings = []
        report = nil
        let t = target
        let opts = options
        task = Task {
            for await ev in FullRecon.run(target: t, options: opts, secrets: KeychainSecrets()) {
                switch ev {
                case .stage(let name, let f): stage = name; fraction = max(fraction, f)
                case .log(let l): log.append(l); if log.count > 300 { log.removeFirst() }
                case .section(let s): sections.append(s)
                case .finding(let f): findings.append(f)
                case .finished(let r):
                    report = r
                    if !r.sections.isEmpty { store.add(r) }
                }
            }
            running = false
        }
    }

    func stop() {
        task?.cancel()
        task = nil
        running = false
        stoppedEarly = true
        stage = "Stopped"
    }
}

struct FullReconView: View {
    @EnvironmentObject private var store: SessionStore
    @StateObject private var model = FullReconModel()
    @State private var showOptions = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("DOMAIN OR IP").font(.caption2.weight(.bold)).foregroundStyle(Theme.dim)
                        TerminalField(placeholder: "example.com", text: $model.target)
                            .submitLabel(.go)
                            .onSubmit { model.start(store: store) }

                        DisclosureGroup(isExpanded: $showOptions) {
                            VStack(alignment: .leading, spacing: 4) {
                                Toggle("DNS records & email security", isOn: $model.options.dnsAndEmail)
                                Toggle("WHOIS / RDAP", isOn: $model.options.whois)
                                Toggle("IP intelligence (geo, ASN, Shodan InternetDB)", isOn: $model.options.ipIntel)
                                Toggle("Certificate Transparency subdomains", isOn: $model.options.certTransparency)
                                Toggle("Subdomain brute-force (+\(Wordlist.subdomains.count) DoH queries)", isOn: $model.options.subdomainBrute)
                                Toggle("Web archive mining", isOn: $model.options.wayback)
                                Toggle("HTTP security & CORS (active)", isOn: $model.options.webChecks)
                                Toggle("Exposed files & paths (active)", isOn: $model.options.contentDiscovery)
                                Toggle("TLS inspection (active)", isOn: $model.options.tls)
                                Toggle("Port scan top 100 (active)", isOn: $model.options.portScan)
                            }
                            .font(.subheadline)
                            .padding(.top, 6)
                        } label: {
                            Text("Modules").font(.subheadline.weight(.semibold))
                        }

                        Label("Includes active scanning of the target. Run only against assets you own or are authorised to test.",
                              systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(Severity.medium.color)

                        HStack {
                            Button { model.start(store: store) } label: {
                                HStack { if model.running { ProgressView().tint(.black) }; Text(model.running ? "Running…" : "Run full recon") }
                            }
                            .buttonStyle(PrimaryButtonStyle())
                            .disabled(model.running || model.target.trimmingCharacters(in: .whitespaces).isEmpty)
                            if model.running {
                                Button("Stop") { model.stop() }.buttonStyle(PrimaryButtonStyle(tint: Severity.high.color)).frame(width: 100)
                            }
                        }
                    }
                    .card()

                    if model.running || model.fraction > 0 {
                        VStack(alignment: .leading, spacing: 8) {
                            ProgressView(value: model.fraction).tint(Theme.accent)
                            Text(model.stage).font(Theme.mono).foregroundStyle(Theme.accent)
                            if model.running {
                                ForEach(Array(model.log.suffix(6).enumerated()), id: \.offset) { _, l in
                                    Text(l).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.dim).lineLimit(1)
                                }
                            }
                        }.card()
                    }

                    if model.stoppedEarly {
                        Label("Scan stopped — results below are incomplete.", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(Severity.high.color)
                    }
                    if !model.findings.isEmpty { FindingsCard(findings: model.findings) }
                    if let r = model.report, let s = r.sections.first {
                        SectionCard(section: s)
                        HStack {
                            ShareLink(item: ReportExporter.markdown(r)) { Label("Share report", systemImage: "square.and.arrow.up") }
                                .buttonStyle(.bordered)
                            Text("Saved to Reports").font(.caption).foregroundStyle(Theme.dim)
                        }
                    }
                    ForEach(model.sections.filter { !$0.title.hasPrefix("Executive summary") }) { SectionCard(section: $0) }
                }
                .padding(16)
            }
            .scrollDismissesKeyboard(.interactively)
            .screenBackground()
            .navigationTitle("Full Recon")
        }
    }
}
