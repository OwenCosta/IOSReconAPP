import SwiftUI

@main
struct ReconKitApp: App {
    @StateObject private var store = SessionStore()
    @StateObject private var notes = NotesStore()
    @StateObject private var ssh = SSHStore()
    @StateObject private var ai = AIStore()
    @StateObject private var entitlements = Entitlements()

    init() {
        let appearance = UINavigationBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = UIColor(Theme.bg)
        appearance.titleTextAttributes = [.foregroundColor: UIColor.white]
        appearance.largeTitleTextAttributes = [.foregroundColor: UIColor.white]
        UINavigationBar.appearance().standardAppearance = appearance
        UINavigationBar.appearance().scrollEdgeAppearance = appearance

        let tab = UITabBarAppearance()
        tab.configureWithOpaqueBackground()
        tab.backgroundColor = UIColor(Theme.bg)
        UITabBar.appearance().standardAppearance = tab
        UITabBar.appearance().scrollEdgeAppearance = tab
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .environmentObject(notes)
                .environmentObject(ssh)
                .environmentObject(ai)
                .environmentObject(entitlements)
                .preferredColorScheme(.dark)
                .tint(Theme.accent)
        }
    }
}
