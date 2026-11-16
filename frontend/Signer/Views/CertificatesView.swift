import SwiftUI
import UniformTypeIdentifiers

struct CertificatesView: View {
    @EnvironmentObject var api: APIClient
    @State private var showUploadSheet = false

    var body: some View {
        NavigationStack {
            List {
                if api.certificates.isEmpty {
                    ContentUnavailableView(
                        "No Certificates",
                        systemImage: "checkmark.seal",
                        description: Text("Upload a .p12 certificate and .mobileprovision profile to sign IPAs.")
                    )
                } else {
                    ForEach(api.certificates) { cert in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(cert.name)
                                .font(.headline)
                            Text("Type: \(cert.certType) • Source: \(cert.source)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text("Expires: \(cert.expiresAt.formatted(date: .abbreviated, time: .omitted))")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .refreshable { await api.fetchCertificates() }
            .navigationTitle("Certificates")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showUploadSheet = true
                    } label: {
                        Image(systemName: "plus.circle.fill")
                            .font(.title3)
                    }
                }
            }
            .sheet(isPresented: $showUploadSheet) {
                UploadCertSheet()
            }
        }
    }
}

private struct UploadCertSheet: View {
    @EnvironmentObject var api: APIClient
    @Environment(\.dismiss) var dismiss

    @State private var name = "My iOS Cert"
    @State private var password = ""
    @State private var p12URL: URL?
    @State private var provURL: URL?
    @State private var pickingP12 = false
    @State private var pickingProv = false
    @State private var isUploading = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Certificate Details") {
                    TextField("Name", text: $name)
                    SecureField("P12 Password (optional)", text: $password)
                }

                Section("Files") {
                    Button(p12URL == nil ? "Select .p12 file" : "P12: \(p12URL!.lastPathComponent)") {
                        pickingP12 = true
                    }
                    Button(provURL == nil ? "Select .mobileprovision file" : "Profile: \(provURL!.lastPathComponent)") {
                        pickingProv = true
                    }
                }

                Section {
                    Button {
                        guard let p12URL, let provURL else { return }
                        Task {
                            isUploading = true
                            await api.uploadCertificate(name: name, password: password, p12URL: p12URL, provURL: provURL)
                            isUploading = false
                            dismiss()
                        }
                    } label: {
                        HStack {
                            Spacer()
                            if isUploading { ProgressView() }
                            else { Text("Upload Certificate").fontWeight(.semibold) }
                            Spacer()
                        }
                    }
                    .disabled(p12URL == nil || provURL == nil || isUploading)
                }
            }
            .navigationTitle("Add Certificate")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .fileImporter(isPresented: $pickingP12, allowedContentTypes: [UTType(filenameExtension: "p12") ?? .data]) { res in
                if case .success(let u) = res { p12URL = u }
            }
            .fileImporter(isPresented: $pickingProv, allowedContentTypes: [UTType(filenameExtension: "mobileprovision") ?? .data]) { res in
                if case .success(let u) = res { provURL = u }
            }
        }
    }
}
