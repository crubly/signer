import SwiftUI

struct LoginView: View {
    @EnvironmentObject var api: APIClient
    @State private var isLoading = false
    @State private var manualIDToken = ""
    @State private var showManualToken = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Spacer()

                Image(systemName: "signature")
                    .font(.system(size: 64, weight: .bold))
                    .foregroundStyle(.blue.gradient)

                VStack(spacing: 8) {
                    Text("Signer")
                        .font(.largeTitle.bold())
                    Text("Remote iOS App Signing & Renewal")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("Backend Server URL")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    TextField("https://sign.yourdomain.com", text: $api.serverURL)
                        .textFieldStyle(.roundedBorder)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
                .padding(.horizontal)

                Button {
                    Task {
                        isLoading = true
                        await api.signInWithGoogleWeb()
                        isLoading = false
                    }
                } label: {
                    HStack {
                        Image(systemName: "person.badge.key.fill")
                        Text(isLoading ? "Connecting..." : "Continue with Google")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(.blue)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .disabled(isLoading)
                .padding(.horizontal)

                Button("Use Google ID Token") {
                    showManualToken.toggle()
                }
                .font(.footnote)
                .foregroundStyle(.secondary)

                if showManualToken {
                    VStack(spacing: 10) {
                        TextField("Paste Google ID Token", text: $manualIDToken)
                            .textFieldStyle(.roundedBorder)
                            .textInputAutocapitalization(.never)
                        Button("Verify Token") {
                            Task {
                                isLoading = true
                                await api.signInWithGoogleIDToken(manualIDToken)
                                isLoading = false
                            }
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    .padding(.horizontal)
                }

                if let err = api.errorMessage {
                    Text(err)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                Spacer()
            }
            .navigationTitle("Welcome")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}
