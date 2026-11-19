import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject var api: APIClient
    @StateObject private var installer = DeviceInstaller.shared
    @State private var showAppleLogin = false
    @State private var showPairingImporter = false
    @State private var pairingStatusMessage: String?
    @State private var ntfyURL = ""
    @State private var webhookURL = ""
    @State private var warningHours = 24

    var body: some View {
        NavigationStack {
            Form {
                Section("Apple Developer Account") {
                    if let acc = api.appleAccount {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(acc.appleID)
                                .font(.headline)
                            Text("Team: \(acc.teamName.isEmpty ? acc.teamID : acc.teamName) (\(acc.teamType))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } else if let user = api.user {
                        Text(user.appleID)
                            .font(.headline)
                    }
                    Button("Switch / Change Apple ID") {
                        showAppleLogin = true
                    }
                    Button("Sign Out", role: .destructive) {
                        api.logout()
                    }
                }

                Section {
                    if installer.hasPairingFile {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Pairing File Loaded")
                                    .font(.subheadline.weight(.semibold))
                                if let udid = installer.deviceUDID {
                                    Text("UDID: \(udid)")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    } else {
                        Label("No Pairing File Imported", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.subheadline)
                    }

                    Button(installer.hasPairingFile ? "Replace Pairing File" : "Import Pairing File (.mobiledevicepairing)") {
                        showPairingImporter = true
                    }

                    if installer.hasPairingFile {
                        Button("Remove Pairing File", role: .destructive) {
                            installer.clearPairingFile()
                        }
                    }

                    TextField("Loopback VPN IP (StosVPN)", text: $installer.vpnIP)
                        .keyboardType(.numbersAndPunctuation)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)

                    if let msg = pairingStatusMessage {
                        Text(msg)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Device Pairing (SideStore Mode)")
                } footer: {
                    Text("For free Apple IDs: generate a .mobiledevicepairing file once via JitterbugPair, import it here, and turn on StosVPN (10.7.0.1) before installing or renewing apps.")
                }

                Section("Expiration & Push Alerts") {
                    TextField("ntfy.sh Topic URL (optional)", text: $ntfyURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Webhook URL (optional)", text: $webhookURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Stepper("Warn \(warningHours)h before expiry", value: $warningHours, in: 1...72)

                    Button("Save Alert Settings") {
                        Task {
                            var st = api.settings ?? PushSettings(
                                publicURL: api.serverURL,
                                anisetteURL: "https://ani.sidestore.io",
                                ntfyURL: "",
                                webhookURL: "",
                                apnsDeviceToken: "",
                                expiryWarningHours: 24
                            )
                            st.ntfyURL = ntfyURL
                            st.webhookURL = webhookURL
                            st.expiryWarningHours = warningHours
                            await api.saveSettings(st)
                        }
                    }

                    Button("Send Test Renewal Alert") {
                        Task { await api.sendTestNotification() }
                    }
                }

                Section("Server") {
                    TextField("Backend URL", text: $api.serverURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                if !api.notifications.isEmpty {
                    Section("Recent Alerts") {
                        ForEach(api.notifications.prefix(10)) { ev in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(ev.title)
                                    .font(.subheadline.weight(.semibold))
                                Text(ev.body)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Settings")
            .onAppear {
                if let st = api.settings {
                    ntfyURL = st.ntfyURL
                    webhookURL = st.webhookURL
                    warningHours = st.expiryWarningHours
                }
            }
            .sheet(isPresented: $showAppleLogin) {
                AppleLoginSheet()
            }
            .fileImporter(
                isPresented: $showPairingImporter,
                allowedContentTypes: [.data, .propertyList, .xml]
            ) { result in
                switch result {
                case .success(let url):
                    do {
                        let udid = try installer.importPairingFile(from: url)
                        pairingStatusMessage = "Pairing file saved!"
                        if let udid, !udid.isEmpty {
                            Task {
                                await api.updateDeviceUDID(udid)
                                pairingStatusMessage = "Pairing file saved & UDID synced to server."
                            }
                        }
                    } catch {
                        pairingStatusMessage = error.localizedDescription
                    }
                case .failure(let err):
                    pairingStatusMessage = err.localizedDescription
                }
            }
        }
    }
}

private struct AppleLoginSheet: View {
    @EnvironmentObject var api: APIClient
    @Environment(\.dismiss) var dismiss

    @State private var appleID = ""
    @State private var password = ""
    @State private var code2FA = ""
    @State private var needs2FA = false
    @State private var isLoading = false

    var body: some View {
        NavigationStack {
            Form {
                if !needs2FA {
                    Section("Apple ID Credentials") {
                        TextField("Apple ID Email", text: $appleID)
                            .keyboardType(.emailAddress)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        SecureField("Password", text: $password)
                    }
                    Section {
                        Button {
                            Task {
                                isLoading = true
                                let twoFA = await api.appleLogin(appleID: appleID, password: password)
                                isLoading = false
                                if twoFA {
                                    needs2FA = true
                                } else if api.appleAccount?.loggedIn == true {
                                    dismiss()
                                }
                            }
                        } label: {
                            if isLoading { ProgressView() }
                            else { Text("Sign In") }
                        }
                        .disabled(appleID.isEmpty || password.isEmpty || isLoading)
                    }
                } else {
                    Section("Two-Factor Authentication") {
                        Text("Enter the 6-digit verification code sent to your trusted Apple device.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        TextField("123456", text: $code2FA)
                            .keyboardType(.numberPad)
                    }
                    Section {
                        Button {
                            Task {
                                isLoading = true
                                let ok = await api.submitApple2FA(code: code2FA)
                                isLoading = false
                                if ok { dismiss() }
                            }
                        } label: {
                            if isLoading { ProgressView() }
                            else { Text("Verify Code") }
                        }
                        .disabled(code2FA.count != 6 || isLoading)
                    }
                }

                if let err = api.errorMessage {
                    Section {
                        Text(err)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Apple ID")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}
