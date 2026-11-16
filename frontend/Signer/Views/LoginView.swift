import SwiftUI

struct LoginView: View {
    @EnvironmentObject var api: APIClient
    @State private var appleID = ""
    @State private var password = ""
    @State private var code2FA = ""
    @State private var needs2FA = false
    @State private var isLoading = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 22) {
                Spacer()

                Image(systemName: "signature")
                    .font(.system(size: 60, weight: .bold))
                    .foregroundStyle(.blue.gradient)

                VStack(spacing: 6) {
                    Text("Signed")
                        .font(.largeTitle.bold())
                    Text("Sign in with your Apple ID to sign & renew apps")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(.horizontal)

                VStack(spacing: 12) {
                    TextField("Server URL (https://sign.yourdomain.com)", text: $api.serverURL)
                        .textFieldStyle(.roundedBorder)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)

                    if !needs2FA {
                        TextField("Apple ID Email", text: $appleID)
                            .textFieldStyle(.roundedBorder)
                            .keyboardType(.emailAddress)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)

                        SecureField("Apple ID Password", text: $password)
                            .textFieldStyle(.roundedBorder)
                    } else {
                        Text("Enter the 6-digit 2FA code sent to your trusted device.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        TextField("6-digit 2FA Code", text: $code2FA)
                            .textFieldStyle(.roundedBorder)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.center)
                    }
                }
                .padding(.horizontal)

                Button {
                    Task {
                        isLoading = true
                        if !needs2FA {
                            let twoFA = await api.appleLogin(appleID: appleID, password: password)
                            if twoFA {
                                needs2FA = true
                            }
                        } else {
                            _ = await api.submitApple2FA(code: code2FA)
                        }
                        isLoading = false
                    }
                } label: {
                    HStack {
                        Image(systemName: "apple.logo")
                        Text(isLoading ? "Signing in..." : (needs2FA ? "Verify 2FA Code" : "Sign In with Apple ID"))
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(.blue)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .disabled(isLoading || (!needs2FA && (appleID.isEmpty || password.isEmpty)) || (needs2FA && code2FA.count != 6))
                .padding(.horizontal)

                if needs2FA {
                    Button("Back to Apple ID") {
                        needs2FA = false
                        code2FA = ""
                    }
                    .font(.footnote)
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
            .navigationTitle("Sign In")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}
