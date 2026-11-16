import SwiftUI

struct ExtensionsView: View {
    @EnvironmentObject var api: APIClient

    var body: some View {
        NavigationStack {
            List {
                if api.appIDs.isEmpty {
                    ContentUnavailableView(
                        "No App IDs / Extensions",
                        systemImage: "puzzlepiece.extension",
                        description: Text("Sign in with your Apple ID in Settings and pull to refresh to manage App IDs & App Extensions.")
                    )
                } else {
                    Section("Registered App IDs & Extensions (\(api.appIDs.count)/10)") {
                        ForEach(api.appIDs) { item in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack(spacing: 6) {
                                        Text(item.name)
                                            .font(.headline)
                                        if item.isExtension {
                                            Text("EXT")
                                                .font(.caption2.bold())
                                                .padding(.horizontal, 5)
                                                .padding(.vertical, 2)
                                                .background(.orange.opacity(0.2))
                                                .foregroundStyle(.orange)
                                                .clipShape(Capsule())
                                        }
                                    }
                                    Text(item.identifier)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button(role: .destructive) {
                                    Task { await api.deleteAppID(item.appIDID) }
                                } label: {
                                    Image(systemName: "trash")
                                }
                                .buttonStyle(.borderless)
                            }
                        }
                    }
                }
            }
            .refreshable { await api.fetchAppIDs() }
            .task { await api.fetchAppIDs() }
            .navigationTitle("App Extensions")
        }
    }
}
