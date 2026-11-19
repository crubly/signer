import Foundation
import Darwin
import IDevice

@MainActor
final class DeviceInstaller: ObservableObject {
    static let shared = DeviceInstaller()

    @Published var hasPairingFile: Bool = false
    @Published var deviceUDID: String?
    @Published var vpnIP: String {
        didSet { UserDefaults.standard.set(vpnIP, forKey: "signed_vpn_ip") }
    }

    private let pairingFileURL: URL

    init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        self.pairingFileURL = docs.appendingPathComponent("pairingFile.plist")
        self.vpnIP = UserDefaults.standard.string(forKey: "signed_vpn_ip") ?? "10.7.0.1"
        refreshPairingState()
    }

    func refreshPairingState() {
        hasPairingFile = FileManager.default.fileExists(atPath: pairingFileURL.path)
        if hasPairingFile,
           let data = try? Data(contentsOf: pairingFileURL),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let udid = plist["UDID"] as? String {
            deviceUDID = udid
        } else {
            deviceUDID = nil
        }
    }

    func importPairingFile(from sourceURL: URL) throws -> String? {
        let accessing = sourceURL.startAccessingSecurityScopedResource()
        defer { if accessing { sourceURL.stopAccessingSecurityScopedResource() } }

        let data = try Data(contentsOf: sourceURL)
        guard let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              plist["HostCertificate"] != nil,
              plist["HostPrivateKey"] != nil else {
            throw NSError(domain: "DeviceInstaller", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Invalid pairing file. Use a .mobiledevicepairing file from JitterbugPair or idevicepair."
            ])
        }

        try data.write(to: pairingFileURL, options: .atomic)
        refreshPairingState()
        return deviceUDID
    }

    func clearPairingFile() {
        try? FileManager.default.removeItem(at: pairingFileURL)
        refreshPairingState()
    }

    func installIPA(from remoteURL: URL, appID: String, onProgress: @escaping @MainActor (String) -> Void) async throws {
        guard hasPairingFile else {
            throw NSError(domain: "DeviceInstaller", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "Pairing file not imported. Import .mobiledevicepairing in Settings first."
            ])
        }

        await onProgress("Downloading signed IPA...")
        let (localTmpURL, resp) = try await URLSession.shared.download(from: remoteURL)
        if let http = resp as? HTTPURLResponse, http.statusCode >= 300 {
            throw NSError(domain: "DeviceInstaller", code: http.statusCode, userInfo: [
                NSLocalizedDescriptionKey: "Failed to download signed IPA (HTTP \(http.statusCode))"
            ])
        }
        defer { try? FileManager.default.removeItem(at: localTmpURL) }

        let ip = vpnIP.trimmingCharacters(in: .whitespacesAndNewlines)
        let pairingPath = pairingFileURL.path
        let remoteFileName = "\(appID).ipa"

        try await Task.detached(priority: .userInitiated) {
            try Self.performLockdownInstall(
                ipaPath: localTmpURL.path,
                pairingPath: pairingPath,
                vpnIP: ip,
                remoteFileName: remoteFileName,
                onProgress: { msg in
                    Task { @MainActor in onProgress(msg) }
                }
            )
        }.value
    }

    private nonisolated static func checkFfiError(_ err: UnsafeMutablePointer<IdeviceFfiError>?, context: String) throws {
        guard let err else { return }
        let msg: String
        if let cMsg = err.pointee.message {
            msg = String(cString: cMsg)
        } else {
            msg = "code \(err.pointee.code)"
        }
        idevice_error_free(err)
        throw NSError(domain: "DeviceInstaller", code: Int(err.pointee.code), userInfo: [
            NSLocalizedDescriptionKey: "\(context): \(msg). Make sure StosVPN is ON."
        ])
    }

    private final class ProgressBox {
        let handler: (String) -> Void
        init(_ handler: @escaping (String) -> Void) { self.handler = handler }
    }

    private nonisolated static func performLockdownInstall(
        ipaPath: String,
        pairingPath: String,
        vpnIP: String,
        remoteFileName: String,
        onProgress: @escaping (String) -> Void
    ) throws {
        onProgress("Connecting to lockdownd (\(vpnIP))...")

        var pairingFile: OpaquePointer?
        try checkFfiError(idevice_pairing_file_read(pairingPath, &pairingFile), context: "Read pairing file")
        guard let pairingFile else {
            throw NSError(domain: "DeviceInstaller", code: 3, userInfo: [NSLocalizedDescriptionKey: "Null pairing file handle"])
        }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(LOCKDOWN_PORT).bigEndian
        guard inet_pton(AF_INET, vpnIP, &addr.sin_addr) == 1 else {
            idevice_pairing_file_free(pairingFile)
            throw NSError(domain: "DeviceInstaller", code: 4, userInfo: [NSLocalizedDescriptionKey: "Invalid VPN IP: \(vpnIP)"])
        }

        var provider: OpaquePointer?
        let provErr = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                idevice_tcp_provider_new(sockPtr, pairingFile, "Signed", &provider)
            }
        }
        try checkFfiError(provErr, context: "Connect TCP provider")
        guard let provider else {
            throw NSError(domain: "DeviceInstaller", code: 5, userInfo: [NSLocalizedDescriptionKey: "Null TCP provider"])
        }
        defer { idevice_provider_free(provider) }

        // 1. Upload IPA via AFC to /PublicStaging/<id>.ipa
        onProgress("Connecting AFC...")
        var afc: OpaquePointer?
        try checkFfiError(afc_client_connect(provider, &afc), context: "AFC connect")
        guard let afc else {
            throw NSError(domain: "DeviceInstaller", code: 6, userInfo: [NSLocalizedDescriptionKey: "Null AFC client"])
        }
        defer { afc_client_free(afc) }

        if let dirErr = afc_make_directory(afc, "PublicStaging") {
            idevice_error_free(dirErr) // Ignore if PublicStaging already exists
        }

        let stagingPath = "PublicStaging/\(remoteFileName)"
        var fileHandle: OpaquePointer?
        try checkFfiError(afc_file_open(afc, stagingPath, AfcWrOnly, &fileHandle), context: "AFC open file")
        guard let fileHandle else {
            throw NSError(domain: "DeviceInstaller", code: 7, userInfo: [NSLocalizedDescriptionKey: "Null AFC file handle"])
        }
        defer { _ = afc_file_close(fileHandle) }

        let fh = try FileHandle(forReadingFrom: URL(fileURLWithPath: ipaPath))
        defer { try? fh.close() }
        let attrs = try FileManager.default.attributesOfItem(atPath: ipaPath)
        let totalBytes = (attrs[.size] as? NSNumber)?.int64Value ?? 1
        var writtenBytes: Int64 = 0
        let chunkSize = 512 * 1024

        while true {
            let chunk = fh.readData(ofLength: chunkSize)
            if chunk.isEmpty { break }
            let writeErr: UnsafeMutablePointer<IdeviceFfiError>? = chunk.withUnsafeBytes { rawBuf in
                guard let base = rawBuf.bindMemory(to: UInt8.self).baseAddress else { return nil }
                return afc_file_write(fileHandle, base, chunk.count)
            }
            try checkFfiError(writeErr, context: "AFC write")
            writtenBytes += Int64(chunk.count)
            let pct = min(100, Int((Double(writtenBytes) / Double(max(totalBytes, 1))) * 100))
            onProgress("Uploading to device: \(pct)%")
        }

        // 2. Install via com.apple.mobile.installation_proxy
        onProgress("Starting iOS installation...")
        var instClient: OpaquePointer?
        try checkFfiError(installation_proxy_connect(provider, &instClient), context: "Installation proxy connect")
        guard let instClient else {
            throw NSError(domain: "DeviceInstaller", code: 8, userInfo: [NSLocalizedDescriptionKey: "Null installation proxy"])
        }
        defer { installation_proxy_client_free(instClient) }

        let box = ProgressBox(onProgress)
        let ctxPtr = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<ProgressBox>.fromOpaque(ctxPtr).release() }

        let cb: @convention(c) (UInt64, UnsafeMutableRawPointer?) -> Void = { progress, rawCtx in
            guard let rawCtx else { return }
            let b = Unmanaged<ProgressBox>.fromOpaque(rawCtx).takeUnretainedValue()
            b.handler("Installing on iPhone: \(progress)%")
        }

        let instErr = installation_proxy_install_with_callback(
            instClient,
            "/\(stagingPath)",
            nil,
            cb,
            ctxPtr
        )
        try checkFfiError(instErr, context: "Install app")
        onProgress("Installed!")
    }
}
