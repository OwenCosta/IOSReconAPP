import SwiftUI
import ReconCore

/// NetTactix Pro upgrade screen (Free vs Pro). Billing is scaffolded — real
/// purchases need StoreKit + App Store Connect; for now a local preview unlock.
struct PaywallView: View {
    @EnvironmentObject private var ent: Entitlements
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    VStack(spacing: 6) {
                        (Text("NET").foregroundColor(Theme.accent) + Text("TACTIX ").foregroundColor(Theme.fg) + Text("PRO").foregroundColor(Theme.accent))
                            .font(.system(size: 28, weight: .bold, design: .monospaced))
                        Text(ent.isPro ? "You're on Pro. Thank you." : "Unlock the full offensive-security suite")
                            .font(.callout).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
                    }.padding(.top, 8)

                    tierCard(title: "Free", price: "$0", items: Entitlements.freeIncludes, accent: false)
                    tierCard(title: "Pro", price: Entitlements.proPriceText, items: Entitlements.proAdds, accent: true, prefix: "Everything in Free, plus:")

                    if ent.isPro {
                        Button(role: .destructive) { ent.reset() } label: { Text("Turn off Pro (preview)") }
                            .padding(.top, 4)
                    } else {
                        Button { ent.devUnlock() } label: { Label("Unlock Pro", systemImage: "lock.open.fill") }
                            .buttonStyle(PrimaryButtonStyle())
                        Text("Billing coming soon via the App Store. During the competition everything is already unlocked, and this preview just shows the planned Pro tier.")
                            .font(.caption2).foregroundStyle(Theme.dim).multilineTextAlignment(.center).padding(.horizontal, 8)
                    }
                }
                .padding(16)
            }
            .screenBackground()
            .navigationTitle("Go Pro").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
        }
    }

    private func tierCard(title: String, price: String, items: [String], accent: Bool, prefix: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(.title3.weight(.bold)).foregroundStyle(accent ? Theme.accent : Theme.fg)
                Spacer()
                Text(price).font(.title3.weight(.semibold)).foregroundStyle(Theme.fg)
            }
            if let p = prefix { Text(p).font(.caption).foregroundStyle(Theme.dim) }
            ForEach(items, id: \.self) { item in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(accent ? Theme.accent : Severity.low.color).font(.caption)
                    Text(item).font(.callout).foregroundStyle(Theme.fg)
                }
            }
        }
        .card()
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(accent ? Theme.accent.opacity(0.5) : Theme.stroke, lineWidth: accent ? 1.5 : 1))
    }
}
