import Foundation

struct UserProfile: Codable, Identifiable {
    let id: String
    let appleID: String
    let dsid: String

    enum CodingKeys: String, CodingKey {
        case id, dsid
        case appleID = "apple_id"
    }
}

struct AppleAccount: Codable {
    let appleID: String
    let teamID: String
    let teamName: String
    let teamType: String
    let loggedIn: Bool
    let needs2FA: Bool

    enum CodingKeys: String, CodingKey {
        case appleID = "apple_id"
        case teamID = "team_id"
        case teamName = "team_name"
        case teamType = "team_type"
        case loggedIn = "logged_in"
        case needs2FA = "needs_2fa"
    }
}

struct SignedApp: Codable, Identifiable {
    let id: String
    let name: String
    let bundleID: String
    let originalBundleID: String
    let version: String
    let certID: String
    let availableExtensions: [String]
    let strippedExtensions: [String]
    let signedAt: Date
    let expiresAt: Date
    let status: String

    enum CodingKeys: String, CodingKey {
        case id, name, version, status
        case bundleID = "bundle_id"
        case originalBundleID = "original_bundle_id"
        case certID = "cert_id"
        case availableExtensions = "available_extensions"
        case strippedExtensions = "stripped_extensions"
        case signedAt = "signed_at"
        case expiresAt = "expires_at"
    }

    var timeRemaining: TimeInterval {
        expiresAt.timeIntervalSinceNow
    }

    var isExpiringSoon: Bool {
        status == "signed" && timeRemaining > 0 && timeRemaining < 48 * 3600
    }

    var isExpired: Bool {
        status == "signed" && timeRemaining <= 0
    }

    var remainingText: String {
        if status != "signed" { return "Not signed" }
        let rem = timeRemaining
        if rem <= 0 { return "Expired — tap Renew" }
        let days = Int(rem) / 86400
        let hours = (Int(rem) % 86400) / 3600
        if days > 0 {
            return "\(days)d \(hours)h left"
        }
        let mins = (Int(rem) % 3600) / 60
        return "\(hours)h \(mins)m left"
    }
}

struct AppIDRecord: Codable, Identifiable {
    var id: String { appIDID }
    let appIDID: String
    let name: String
    let identifier: String
    let isExtension: Bool

    enum CodingKeys: String, CodingKey {
        case appIDID = "app_id_id"
        case name, identifier
        case isExtension = "is_extension"
    }
}

struct SigningCertificate: Codable, Identifiable {
    let id: String
    let name: String
    let certType: String
    let expiresAt: Date
    let source: String

    enum CodingKeys: String, CodingKey {
        case id, name, source
        case certType = "cert_type"
        case expiresAt = "expires_at"
    }
}

struct NotificationEvent: Codable, Identifiable {
    let id: String
    let appID: String
    let appName: String
    let title: String
    let body: String
    let level: String
    let createdAt: Date
    let read: Bool

    enum CodingKeys: String, CodingKey {
        case id, title, body, level, read
        case appID = "app_id"
        case appName = "app_name"
        case createdAt = "created_at"
    }
}

struct PushSettings: Codable {
    var publicURL: String
    var anisetteURL: String
    var ntfyURL: String
    var webhookURL: String
    var apnsDeviceToken: String
    var expiryWarningHours: Int

    enum CodingKeys: String, CodingKey {
        case publicURL = "public_url"
        case anisetteURL = "anisette_url"
        case ntfyURL = "ntfy_url"
        case webhookURL = "webhook_url"
        case apnsDeviceToken = "apns_device_token"
        case expiryWarningHours = "expiry_warning_hours"
    }
}

struct SignResponse: Codable {
    let app: SignedApp
    let otaURL: String
    let ipaURL: String?

    enum CodingKeys: String, CodingKey {
        case app
        case otaURL = "ota_url"
        case ipaURL = "ipa_url"
    }
}
