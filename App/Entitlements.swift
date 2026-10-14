import SwiftUI

/// NetTactix tiering. The business model is Free vs Pro ($5/mo), but during the
/// competition nothing is locked — gating is opt-in and not yet applied to any
/// feature. When you ship, wire `upgrade()` to StoreKit and call `gate()` where
/// you want a Pro wall.
@MainActor
final class Entitlements: ObservableObject {
    /// Whether the user has Pro. Persisted. Real purchases arrive via StoreKit later.
    @AppStorage("nettactix.isPro") var isPro: Bool = false

    static let proPriceText = "$5/mo"

    struct Feature: Identifiable { let id = UUID(); let name: String; let free: Bool }

    /// Product preview — what Free includes and what Pro adds. Not enforced yet.
    static let freeIncludes: [String] = [
        "Port scanner, LAN discovery & Bonjour",
        "Full Recon pipeline (DNS, web, TLS, ports)",
        "CTF / crypto toolkit & Magic Decoder",
        "OSINT, DNS & web tools",
        "MITRE ATT&CK browser & Learn guide",
        "Bluetooth (BLE) scanner",
    ]
    static let proAdds: [String] = [
        "AI Copilot with unlimited chats & providers",
        "SSH terminal + SFTP file browser",
        "IP camera recon & RTSP toolkit",
        "Deep recon pipelines & scheduled re-scans",
        "Unlimited saved reports, export & sync",
        "Priority new tools & no limits",
    ]

    /// Opt-in gate helper. Currently always allows (nothing locked for the comp).
    /// Flip `enforce` to true when launching the paid tier.
    static let enforce = false
    func allowed(_ proFeature: Bool) -> Bool { !Self.enforce || !proFeature || isPro }

    /// Local unlock so the team can preview "Pro" without StoreKit yet.
    func devUnlock() { isPro = true }
    func reset() { isPro = false }
}
