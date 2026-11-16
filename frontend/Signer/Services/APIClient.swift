import Foundation
import UIKit

@MainActor
final class APIClient: ObservableObject {
    static let shared = APIClient()

    @Published var serverURL: String {
        didSet { UserDefaults.standard.set(serverURL, forKey: "signer_server_url") }
    }
    @Published var jwtToken: String? {
        didSet {
            if let jwtToken {
                KeychainHelper.save(jwtToken, key: "jwt_token")
            } else {
                KeychainHelper.delete(key: "jwt_token")
            }
        }
    }
    @Published var user: UserProfile?
    @Published var appleAccount: AppleAccount?
    @Published var pendingSessionID: String?
    @Published var apps: [SignedApp] = []
    @Published var appIDs: [AppIDRecord] = []
    @Published var certificates: [SigningCertificate] = []
    @Published var notifications: [NotificationEvent] = []
    @Published var settings: PushSettings?
    @Published var errorMessage: String?

    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    init() {
        self.serverURL = UserDefaults.standard.string(forKey: "signer_server_url") ?? "https://sign.yourdomain.com"
        self.jwtToken = KeychainHelper.load(key: "jwt_token")
    }

    var isLoggedIn: Bool {
        jwtToken != nil && !(jwtToken?.isEmpty ?? true)
    }

    func logout() {
        jwtToken = nil
        pendingSessionID = nil
        user = nil
        appleAccount = nil
        apps = []
        appIDs = []
        certificates = []
        notifications = []
    }

    func refreshAll() async {
        guard isLoggedIn else { return }
        await fetchMe()
        await fetchApps()
        await fetchCertificates()
        await fetchNotifications()
        await fetchSettings()
    }

    func fetchMe() async {
        do {
            let data = try await request("GET", "/api/auth/me")
            struct MeResp: Codable {
                let user: UserProfile
                let appleAccount: AppleAccount?
                enum CodingKeys: String, CodingKey {
                    case user
                    case appleAccount = "apple_account"
                }
            }
            let res = try decoder.decode(MeResp.self, from: data)
            self.user = res.user
            self.appleAccount = res.appleAccount
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func appleLogin(appleID: String, password: String) async -> Bool {
        errorMessage = nil
        do {
            let udid = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
            let payload: [String: String] = [
                "apple_id": appleID,
                "password": password,
                "device_udid": udid,
                "device_name": UIDevice.current.name
            ]
            let body = try JSONEncoder().encode(payload)
            let data = try await request("POST", "/api/apple/login", body: body, auth: false)
            struct Resp: Codable {
                let needs2FA: Bool
                let sessionID: String?
                let token: String?
                let user: UserProfile?
                let account: AppleAccount
                enum CodingKeys: String, CodingKey {
                    case needs2FA = "needs_2fa"
                    case sessionID = "session_id"
                    case token, user, account
                }
            }
            let res = try decoder.decode(Resp.self, from: data)
            self.appleAccount = res.account
            if res.needs2FA {
                self.pendingSessionID = res.sessionID
                return true
            }
            if let token = res.token {
                self.jwtToken = token
                self.user = res.user
                await refreshAll()
            }
            return false
        } catch {
            self.errorMessage = error.localizedDescription
            return false
        }
    }

    func submitApple2FA(code: String) async -> Bool {
        errorMessage = nil
        guard let sessionID = pendingSessionID else {
            errorMessage = "Missing 2FA session"
            return false
        }
        do {
            let body = try JSONEncoder().encode(["session_id": sessionID, "code": code])
            let data = try await request("POST", "/api/apple/2fa", body: body, auth: false)
            struct Resp: Codable {
                let token: String
                let user: UserProfile
                let account: AppleAccount
            }
            let res = try decoder.decode(Resp.self, from: data)
            self.pendingSessionID = nil
            self.jwtToken = res.token
            self.user = res.user
            self.appleAccount = res.account
            await refreshAll()
            return true
        } catch {
            self.errorMessage = error.localizedDescription
            return false
        }
    }

    func fetchApps() async {
        do {
            let data = try await request("GET", "/api/apps")
            struct Resp: Codable { let apps: [SignedApp] }
            let res = try decoder.decode(Resp.self, from: data)
            self.apps = res.apps
            NotificationManager.shared.scheduleExpirationAlerts(for: res.apps)
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func uploadIPA(fileURL: URL) async -> SignedApp? {
        do {
            let accessing = fileURL.startAccessingSecurityScopedResource()
            defer { if accessing { fileURL.stopAccessingSecurityScopedResource() } }
            let fileData = try Data(contentsOf: fileURL)
            let data = try await uploadMultipart(path: "/api/apps/upload", files: [("ipa", fileURL.lastPathComponent, fileData)], fields: [:])
            let app = try decoder.decode(SignedApp.self, from: data)
            await fetchApps()
            return app
        } catch {
            self.errorMessage = error.localizedDescription
            return nil
        }
    }

    func importIPAFromURL(_ ipaURL: String) async -> SignedApp? {
        do {
            let body = try JSONEncoder().encode(["url": ipaURL])
            let data = try await request("POST", "/api/apps/from-url", body: body)
            let app = try decoder.decode(SignedApp.self, from: data)
            await fetchApps()
            return app
        } catch {
            self.errorMessage = error.localizedDescription
            return nil
        }
    }

    func signApp(id: String, certID: String, bundleID: String, stripExtensions: [String]) async -> SignResponse? {
        do {
            struct SignReq: Codable {
                let certID: String
                let bundleID: String
                let stripExtensions: [String]
                enum CodingKeys: String, CodingKey {
                    case certID = "cert_id"
                    case bundleID = "bundle_id"
                    case stripExtensions = "strip_extensions"
                }
            }
            let body = try JSONEncoder().encode(SignReq(certID: certID, bundleID: bundleID, stripExtensions: stripExtensions))
            let data = try await request("POST", "/api/apps/\(id)/sign", body: body)
            let res = try decoder.decode(SignResponse.self, from: data)
            await fetchApps()
            return res
        } catch {
            self.errorMessage = error.localizedDescription
            return nil
        }
    }

    func renewApp(id: String) async -> SignResponse? {
        do {
            let data = try await request("POST", "/api/apps/\(id)/renew")
            let res = try decoder.decode(SignResponse.self, from: data)
            await fetchApps()
            return res
        } catch {
            self.errorMessage = error.localizedDescription
            return nil
        }
    }

    func deleteApp(id: String) async {
        do {
            _ = try await request("DELETE", "/api/apps/\(id)")
            await fetchApps()
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func fetchAppIDs() async {
        do {
            let data = try await request("GET", "/api/apple/app-ids")
            struct Resp: Codable { let appIDs: [AppIDRecord]
                enum CodingKeys: String, CodingKey { case appIDs = "app_ids" }
            }
            let res = try decoder.decode(Resp.self, from: data)
            self.appIDs = res.appIDs
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func deleteAppID(_ id: String) async {
        do {
            _ = try await request("DELETE", "/api/apple/app-ids/\(id)")
            await fetchAppIDs()
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func fetchCertificates() async {
        do {
            let data = try await request("GET", "/api/certs")
            struct Resp: Codable { let certificates: [SigningCertificate] }
            let res = try decoder.decode(Resp.self, from: data)
            self.certificates = res.certificates
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func uploadCertificate(name: String, password: String, p12URL: URL, provURL: URL) async {
        do {
            let a1 = p12URL.startAccessingSecurityScopedResource()
            let a2 = provURL.startAccessingSecurityScopedResource()
            defer {
                if a1 { p12URL.stopAccessingSecurityScopedResource() }
                if a2 { provURL.stopAccessingSecurityScopedResource() }
            }
            let p12Data = try Data(contentsOf: p12URL)
            let provData = try Data(contentsOf: provURL)
            _ = try await uploadMultipart(
                path: "/api/certs/upload",
                files: [
                    ("p12", p12URL.lastPathComponent, p12Data),
                    ("mobileprovision", provURL.lastPathComponent, provData)
                ],
                fields: ["name": name, "password": password]
            )
            await fetchCertificates()
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func fetchNotifications() async {
        do {
            let data = try await request("GET", "/api/notifications")
            struct Resp: Codable { let notifications: [NotificationEvent] }
            let res = try decoder.decode(Resp.self, from: data)
            self.notifications = res.notifications
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func sendTestNotification() async {
        do {
            _ = try await request("POST", "/api/notifications/test")
            NotificationManager.shared.sendImmediateLocalAlert(
                title: "Signer: Renewal Reminder",
                body: "Test alert — your signed apps will notify you before expiring!"
            )
            await fetchNotifications()
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func fetchSettings() async {
        do {
            let data = try await request("GET", "/api/settings")
            self.settings = try decoder.decode(PushSettings.self, from: data)
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func saveSettings(_ st: PushSettings) async {
        do {
            let body = try JSONEncoder().encode(st)
            let data = try await request("PUT", "/api/settings", body: body)
            self.settings = try decoder.decode(PushSettings.self, from: data)
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    // MARK: - HTTP Helpers

    private func request(_ method: String, _ path: String, body: Data? = nil, auth: Bool = true) async throws -> Data {
        let base = serverURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: base + path) else {
            throw URLError(.badURL)
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 60
        if let body {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        if auth, let jwtToken {
            req.setValue("Bearer \(jwtToken)", forHTTPHeaderField: "Authorization")
        }
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        if http.statusCode >= 300 {
            if let errObj = try? JSONDecoder().decode([String: String].self, from: data),
               let msg = errObj["error"] {
                throw NSError(domain: "SignerAPI", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: msg])
            }
            throw NSError(domain: "SignerAPI", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "HTTP \(http.statusCode)"])
        }
        return data
    }

    private func uploadMultipart(path: String, files: [(String, String, Data)], fields: [String: String]) async throws -> Data {
        let base = serverURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: base + path) else { throw URLError(.badURL) }
        let boundary = "Boundary-\(UUID().uuidString)"
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 300
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        if let jwtToken {
            req.setValue("Bearer \(jwtToken)", forHTTPHeaderField: "Authorization")
        }

        var body = Data()
        for (k, v) in fields {
            body.append("--\(boundary)\r\n".data(using: .utf8)!)
            body.append("Content-Disposition: form-data; name=\"\(k)\"\r\n\r\n".data(using: .utf8)!)
            body.append("\(v)\r\n".data(using: .utf8)!)
        }
        for (field, filename, data) in files {
            body.append("--\(boundary)\r\n".data(using: .utf8)!)
            body.append("Content-Disposition: form-data; name=\"\(field)\"; filename=\"\(filename)\"\r\n".data(using: .utf8)!)
            body.append("Content-Type: application/octet-stream\r\n\r\n".data(using: .utf8)!)
            body.append(data)
            body.append("\r\n".data(using: .utf8)!)
        }
        body.append("--\(boundary)--\r\n".data(using: .utf8)!)
        req.httpBody = body

        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, http.statusCode < 300 else {
            let msg = (try? JSONDecoder().decode([String: String].self, from: data))?["error"] ?? "Upload failed"
            throw NSError(domain: "SignerAPI", code: 400, userInfo: [NSLocalizedDescriptionKey: msg])
        }
        return data
    }
}
