import Foundation
import UserNotifications

final class NotificationManager {
    static let shared = NotificationManager()
    private init() {}

    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { _, _ in }
    }

    func scheduleExpirationAlerts(for apps: [SignedApp]) {
        let center = UNUserNotificationCenter.current()
        center.removeAllPendingNotificationRequests()

        let offsets: [(TimeInterval, String)] = [
            (48 * 3600, "expires in 48 hours"),
            (24 * 3600, "expires in 24 hours"),
            (6 * 3600, "expires in 6 hours — renew soon!"),
            (0, "expired — open Signer to re-sign")
        ]

        for app in apps where app.status == "signed" {
            for (offset, label) in offsets {
                let fireDate = app.expiresAt.addingTimeInterval(-offset)
                guard fireDate > Date() else { continue }

                let content = UNMutableNotificationContent()
                content.title = "Signer: \(app.name)"
                content.body = "\(app.name) \(label). Open Signer to extend signature."
                content.sound = .default

                let comps = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute, .second], from: fireDate)
                let trigger = UNCalendarNotificationTrigger(dateMatching: comps, repeats: false)
                let req = UNNotificationRequest(identifier: "\(app.id)-\(Int(offset))", content: content, trigger: trigger)
                center.add(req)
            }
        }
    }

    func sendImmediateLocalAlert(title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }
}
