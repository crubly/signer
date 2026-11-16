import SwiftUI

struct ContentView: View {
    @EnvironmentObject var api: APIClient

    var body: some View {
        Group {
            if api.isLoggedIn {
                TabView {
                    AppsView()
                        .tabItem {
                            Label("Apps", systemImage: "square.stack.3d.up.fill")
                        }
                    ExtensionsView()
                        .tabItem {
                            Label("Extensions", systemImage: "puzzlepiece.extension.fill")
                        }
                    CertificatesView()
                        .tabItem {
                            Label("Certs", systemImage: "checkmark.seal.fill")
                        }
                    SettingsView()
                        .tabItem {
                            Label("Settings", systemImage: "gearshape.fill")
                        }
                }
                .task {
                    await api.refreshAll()
                }
            } else {
                LoginView()
            }
        }
    }
}
