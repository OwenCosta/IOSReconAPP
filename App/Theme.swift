import SwiftUI
import ReconCore

enum Theme {
    static let bg = Color(red: 0.035, green: 0.043, blue: 0.059)
    static let card = Color(red: 0.075, green: 0.09, blue: 0.118)
    static let stroke = Color.white.opacity(0.08)
    static let accent = Color(red: 0.24, green: 0.95, blue: 0.56)
    static let dim = Color.white.opacity(0.55)
    static let mono = Font.system(.footnote, design: .monospaced)
}

extension Severity {
    var color: Color {
        switch self {
        case .info: return Color.white.opacity(0.35)
        case .low: return Color(red: 0.35, green: 0.75, blue: 1.0)
        case .medium: return Color(red: 1.0, green: 0.78, blue: 0.2)
        case .high: return Color(red: 1.0, green: 0.45, blue: 0.2)
        case .critical: return Color(red: 1.0, green: 0.24, blue: 0.3)
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
