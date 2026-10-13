import SwiftUI
import ReconCore

enum Theme {
    // Cold-ink base; a single desaturated signal-cyan carries interaction, while the warm
    // blue→amber→orange→red ramp is reserved strictly for severity (see Severity.color).
    static let bg = Color(red: 0.039, green: 0.055, blue: 0.078)      // #0A0E14
    static let card = Color(red: 0.071, green: 0.094, blue: 0.141)    // #121824
    static let raised = Color(red: 0.102, green: 0.133, blue: 0.192)  // #1A2231
    static let stroke = Color.white.opacity(0.075)
    static let accent = Color(red: 0.224, green: 0.761, blue: 0.788)  // #39C2C9 signal cyan
    static let fg = Color(red: 0.902, green: 0.914, blue: 0.937)      // #E6E9EF cool white
    static let dim = Color(red: 0.902, green: 0.914, blue: 0.937).opacity(0.55)
    static let mono = Font.system(.footnote, design: .monospaced)
}

extension Severity {
    var color: Color {
        switch self {
        case .info: return Color(red: 0.902, green: 0.914, blue: 0.937).opacity(0.4)
        case .low: return Color(red: 0.310, green: 0.663, blue: 0.949)      // #4FA9F2
        case .medium: return Color(red: 0.941, green: 0.722, blue: 0.278)   // #F0B847
        case .high: return Color(red: 0.941, green: 0.518, blue: 0.235)     // #F0843C
        case .critical: return Color(red: 0.941, green: 0.333, blue: 0.420) // #F0556B
        }
    }
    var title: String { rawValue.uppercased() }
}

struct CardStyle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Theme.stroke, lineWidth: 1))
    }
}

extension View {
    func card() -> some View { modifier(CardStyle()) }

    func screenBackground() -> some View {
        background(Theme.bg.ignoresSafeArea())
    }
}

struct SeverityChip: View {
    let severity: Severity
    var body: some View {
        Text(severity.title)
            .font(.system(size: 10, weight: .bold, design: .monospaced))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(severity.color.opacity(0.18), in: Capsule())
            .foregroundStyle(severity.color)
    }
}

struct PrimaryButtonStyle: ButtonStyle {
    var tint: Color = Theme.accent
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(.body, design: .rounded).weight(.semibold))
            .foregroundStyle(Color.black)
            .padding(.vertical, 12).padding(.horizontal, 18)
            .frame(maxWidth: .infinity)
            .background(tint.opacity(configuration.isPressed ? 0.7 : 1), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

struct TerminalField: View {
    let placeholder: String
    @Binding var text: String
    var secure = false
    var body: some View {
        Group {
            if secure { SecureField(placeholder, text: $text) }
            else { TextField(placeholder, text: $text) }
        }
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .font(.system(.body, design: .monospaced))
        .padding(12)
        .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Theme.stroke, lineWidth: 1))
    }
}
