import SwiftUI
import BackgroundTasks

@main
struct SignerApp: App {
    @StateObject private var api = APIClient.shared

    init() {
        NotificationManager.shared.requestPermission()
        BGTaskScheduler.shared.register(forTaskWithIdentifier: "com.crubly.signed.refresh", using: nil) { task in
            guard let refreshTask = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            Task { @MainActor in
                await APIClient.shared.fetchApps()
                let expiring = APIClient.shared.apps.filter { $0.isExpiringSoon || $0.isExpired }
                if !expiring.isEmpty {
                    let names = expiring.map(\.name).joined(separator: ", ")
                    NotificationManager.shared.sendImmediateLocalAlert(
                        title: "Apps Need Renewal",
                        body: "\(names) expiring soon — open Signer to renew."
                    )
                }
                refreshTask.setTaskCompleted(success: true)
            }
            Self.scheduleBackgroundRefresh()
        }
        Self.scheduleBackgroundRefresh()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(api)
        }
    }

    static func scheduleBackgroundRefresh() {
        let req = BGAppRefreshTaskRequest(identifier: "com.crubly.signed.refresh")
        req.earliestBeginDate = Date(timeIntervalSinceNow: 4 * 3600)
        try? BGTaskScheduler.shared.submit(req)
    }
}
