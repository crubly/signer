import SwiftUI
import UniformTypeIdentifiers

struct AppsView: View {
    @EnvironmentObject var api: APIClient
    @State private var showFileImporter = false
    @State private var showURLPrompt = false
    @State private var ipaURLText = ""
    @State private var appToSign: SignedApp?
    @State private var isBusy = false

    var body: some View {
        NavigationStack {
            List {
                if api.apps.isEmpty {
                    ContentUnavailableView(
                        "No Apps Yet",
                        systemImage: "app.dashed",
                        description: Text("Import an .ipa file or URL to sign it on your server.")
                    )
                } else {
                    ForEach(api.apps) { app in
                        AppRow(app: app, onSign: {
                            appToSign = app
                        }, onRenew: {
                            Task {
                                isBusy = true
                                if let res = await api.renewApp(id: app.id),
                                   let url = URL(string: res.otaURL) {
                                    await UIApplication.shared.open(url)
                                }
                                isBusy = false
                            }
                        }, onInstall: {
                            let base = api.serverURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                            let manifest = "\(base)/ota/\(app.id)/manifest.plist"
                            if let encoded = manifest.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
                               let ota = URL(string: "itms-services://?action=download-manifest&url=\(encoded)") {
                                UIApplication.shared.open(ota)
                            }
                        })
                    }
                    .onDelete { offsets in
                        for idx in offsets {
                            let app = api.apps[idx]
                            Task { await api.deleteApp(id: app.id) }
                        }
                    }
                }
            }
            .refreshable { await api.fetchApps() }
            .navigationTitle("Apps")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            showFileImporter = true
                        } label: {
                            Label("Import .ipa from Files", systemImage: "doc.badge.plus")
                        }
                        Button {
                            showURLPrompt = true
                        } label: {
                            Label("Import .ipa from URL", systemImage: "link")
                        }
                    } label: {
                        Image(systemName: "plus.circle.fill")
                            .font(.title3)
                    }
                }
            }
            .fileImporter(
                isPresented: $showFileImporter,
                allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data]
            ) { result in
                if case .success(let url) = result {
                    Task {
                        isBusy = true
                        if let uploaded = await api.uploadIPA(fileURL: url) {
                            appToSign = uploaded
                        }
                        isBusy = false
                    }
                }
            }
            .alert("Import IPA URL", isPresented: $showURLPrompt) {
                TextField("https://example.com/app.ipa", text: $ipaURLText)
                Button("Import") {
                    Task {
                        isBusy = true
                        if let uploaded = await api.importIPAFromURL(ipaURLText) {
                            appToSign = uploaded
                        }
                        ipaURLText = ""
                        isBusy = false
                    }
                }
                Button("Cancel", role: .cancel) {}
            }
            .sheet(item: $appToSign) { app in
                SignAppSheet(app: app)
            }
            .overlay {
                if isBusy {
                    ProgressView("Working on server...")
                        .padding()
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
            }
        }
    }
}

private struct AppRow: View {
    let app: SignedApp
    let onSign: () -> Void
    let onRenew: () -> Void
    let onInstall: () -> Void

    var badgeColor: Color {
        if app.status != "signed" { return .gray }
        if app.isExpired { return .red }
        if app.isExpiringSoon { return .orange }
        return .green
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(app.name)
                        .font(.headline)
                    Text("\(app.bundleID) • v\(app.version)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(app.remainingText)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(badgeColor.opacity(0.15))
                    .foregroundStyle(badgeColor)
                    .clipShape(Capsule())
            }

            if !app.strippedExtensions.isEmpty {
                Text("Stripped extensions: \(app.strippedExtensions.joined(separator: ", "))")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 10) {
                if app.status == "signed" {
                    Button("Install OTA", action: onInstall)
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)

                    Button("Renew", action: onRenew)
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                }
                Button("Sign Options", action: onSign)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 4)
    }
}

private struct SignAppSheet: View {
    @EnvironmentObject var api: APIClient
    @Environment(\.dismiss) var dismiss
    let app: SignedApp

    @State private var selectedCertID = ""
    @State private var bundleID = ""
    @State private var stripExts: Set<String> = []
    @State private var isSigning = false

    var body: some View {
        NavigationStack {
            Form {
                Section("App Info") {
                    Text("Name: \(app.name)")
                    TextField("Bundle ID", text: $bundleID)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section("Certificate") {
                    if api.certificates.isEmpty {
                        Text("No certificates uploaded. Add .p12 + .mobileprovision in Certs tab.")
                            .font(.caption)
                            .foregroundStyle(.red)
                    } else {
                        Picker("Signing Cert", selection: $selectedCertID) {
                            ForEach(api.certificates) { cert in
                                Text(cert.name).tag(cert.id)
                            }
                        }
                    }
                }

                if !app.availableExtensions.isEmpty {
                    Section("App Extensions (Toggle to Remove)") {
                        ForEach(app.availableExtensions, id: \.self) { ext in
                            Toggle(ext, isOn: Binding(
                                get: { stripExts.contains(ext) },
                                set: { remove in
                                    if remove { stripExts.insert(ext) }
                                    else { stripExts.remove(ext) }
                                }
                            ))
                        }
                        Button("Remove All Extensions") {
                            stripExts = Set(app.availableExtensions)
                        }
                        .foregroundStyle(.red)
                    }
                }

                Section {
                    Button {
                        Task {
                            isSigning = true
                            if let res = await api.signApp(
                                id: app.id,
                                certID: selectedCertID,
                                bundleID: bundleID,
                                stripExtensions: Array(stripExts)
                            ) {
                                dismiss()
                                if let url = URL(string: res.otaURL) {
                                    await UIApplication.shared.open(url)
                                }
                            }
                            isSigning = false
                        }
                    } label: {
                        HStack {
                            Spacer()
                            if isSigning {
                                ProgressView()
                            } else {
                                Text("Sign & Install OTA")
                                    .fontWeight(.semibold)
                            }
                            Spacer()
                        }
                    }
                    .disabled(isSigning || api.certificates.isEmpty)
                }
            }
            .navigationTitle("Sign \(app.name)")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onAppear {
                bundleID = app.bundleID
                stripExts = Set(app.strippedExtensions)
                if selectedCertID.isEmpty, let first = api.certificates.first {
                    selectedCertID = first.id
                }
            }
        }
    }
}
