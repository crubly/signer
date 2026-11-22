import Foundation
import Darwin
import Network
import IDevice

@MainActor
final class DeviceInstaller: ObservableObject {
    static let shared = DeviceInstaller()

    enum PairingMode: String {
        case lockdown
        case rppairing
    }

    @Published var hasPairingFile: Bool = false
    @Published var deviceUDID: String?
    @Published var pairingMode: PairingMode?
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
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            if plist["private_key"] != nil && plist["public_key"] != nil && plist["identifier"] != nil {
                pairingMode = .rppairing
                deviceUDID = plist["identifier"] as? String
            } else {
                pairingMode = .lockdown
                deviceUDID = plist["UDID"] as? String
            }
        } else {
            pairingMode = nil
            deviceUDID = nil
        }
    }

    func importPairingFile(from sourceURL: URL) throws -> String? {
        let accessing = sourceURL.startAccessingSecurityScopedResource()
        defer { if accessing { sourceURL.stopAccessingSecurityScopedResource() } }

        let data = try Data(contentsOf: sourceURL)
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw NSError(domain: "DeviceInstaller", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Invalid pairing file. Could not parse property list."
            ])
        }

        let isRP = plist["private_key"] != nil && plist["public_key"] != nil && plist["identifier"] != nil
        let isLockdown = plist["HostCertificate"] != nil && plist["HostPrivateKey"] != nil

        guard isRP || isLockdown else {
            throw NSError(domain: "DeviceInstaller", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Invalid pairing file. Use a .mobiledevicepairing or .rppairing file."
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
                NSLocalizedDescriptionKey: "Pairing file not imported. Import a pairing file in Settings first."
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
        let pairingData = try Data(contentsOf: pairingFileURL)
        let mode = pairingMode ?? .lockdown
        let remoteFileName = "\(appID).ipa"

        var rpPort: UInt16 = 49152
        if mode == .rppairing {
            await onProgress("Discovering RemotePairing port...")
            if let discovered = await Self.discoverRemotePairingPort() {
                rpPort = discovered
            }
        }

        try await Task.detached(priority: .userInitiated) {
            switch mode {
            case .lockdown:
                try Self.performLockdownInstall(
                    ipaPath: localTmpURL.path,
                    pairingData: pairingData,
                    vpnIP: ip,
                    remoteFileName: remoteFileName,
                    onProgress: { msg in
                        Task { @MainActor in onProgress(msg) }
                    }
                )
            case .rppairing:
                try Self.performRPPairingInstall(
                    ipaPath: localTmpURL.path,
                    pairingData: pairingData,
                    vpnIP: ip,
                    port: rpPort,
                    remoteFileName: remoteFileName,
                    onProgress: { msg in
                        Task { @MainActor in onProgress(msg) }
                    }
                )
            }
        }.value
    }

    private nonisolated static func discoverRemotePairingPort(timeout: TimeInterval = 2.5) async -> UInt16? {
        let descriptor = NWBrowser.Descriptor.bonjour(type: "_remotepairing._tcp", domain: nil)
        let params = NWParameters.tcp
        params.includePeerToPeer = true
        let browser = NWBrowser(for: descriptor, using: params)

        return await withCheckedContinuation { continuation in
            let lock = NSLock()
            var resumed = false
            var activeConn: NWConnection?

            @Sendable func finish(_ port: UInt16?) {
                lock.lock()
                guard !resumed else {
                    lock.unlock()
                    return
                }
                resumed = true
                let c = activeConn
                activeConn = nil
                lock.unlock()
                browser.cancel()
                c?.cancel()
                continuation.resume(returning: port)
            }

            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                finish(nil)
            }

            browser.browseResultsChangedHandler = { results, _ in
                guard let target = results.first else { return }
                let conn = NWConnection(to: target.endpoint, using: params)
                lock.lock()
                activeConn = conn
                lock.unlock()

                conn.pathUpdateHandler = { path in
                    if path.status == .satisfied, let remote = path.remoteEndpoint,
                       case .hostPort(_, let port) = remote, port.rawValue > 0 {
                        finish(port.rawValue)
                    }
                }
                conn.stateUpdateHandler = { state in
                    switch state {
                    case .ready, .waiting:
                        if let remote = conn.currentPath?.remoteEndpoint,
                           case .hostPort(_, let port) = remote, port.rawValue > 0 {
                            finish(port.rawValue)
                        }
                    case .failed:
                        finish(nil)
                    default:
                        break
                    }
                }
                conn.start(queue: .global(qos: .userInitiated))
            }

            browser.stateUpdateHandler = { state in
                if case .failed = state {
                    finish(nil)
                }
            }
            browser.start(queue: .global(qos: .userInitiated))
        }
    }

    private nonisolated static func checkFfiError(_ err: UnsafeMutablePointer<IdeviceFfiError>?, context: String) throws {
        guard let err else { return }
        let code = Int(err.pointee.code)
        let msg: String
        if let cMsg = err.pointee.message {
            msg = String(cString: cMsg)
        } else {
            msg = "code \(code)"
        }
        idevice_error_free(err)
        throw NSError(domain: "DeviceInstaller", code: code, userInfo: [
            NSLocalizedDescriptionKey: "\(context): \(msg). Make sure StosVPN is ON."
        ])
    }

    private final class ProgressBox {
        let handler: (String) -> Void
        init(_ handler: @escaping (String) -> Void) { self.handler = handler }
    }

    private final class HeartbeatKeeper: @unchecked Sendable {
        private let lock = NSLock()
        private var active = true
        private var client: OpaquePointer?

        init(client: OpaquePointer) {
            self.client = client
            let thread = Thread { [weak self] in
                var interval: UInt64 = 15
                while let self = self, self.isActive {
                    guard let c = self.getClient() else { break }
                    var nextInterval: UInt64 = 0
                    if let err = heartbeat_get_marco(c, interval, &nextInterval) {
                        idevice_error_free(err)
                        break
                    }
                    interval = max(nextInterval + 5, 10)
                    if let err = heartbeat_send_polo(c) {
                        idevice_error_free(err)
                        break
                    }
                }
            }
            thread.name = "SignedHeartbeat"
            thread.start()
        }

        private var isActive: Bool {
            lock.lock()
            defer { lock.unlock() }
            return active
        }

        private func getClient() -> OpaquePointer? {
            lock.lock()
            defer { lock.unlock() }
            return active ? client : nil
        }

        func stop() {
            lock.lock()
            active = false
            let c = client
            client = nil
            lock.unlock()
            if let c {
                heartbeat_client_free(c)
            }
        }

        deinit {
            stop()
        }
    }

    private nonisolated static func makePairingFile(from data: Data) throws -> OpaquePointer {
        var pf: OpaquePointer?
        let err = data.withUnsafeBytes { buf -> UnsafeMutablePointer<IdeviceFfiError>? in
            guard let base = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            return idevice_pairing_file_from_bytes(base, UInt(data.count), &pf)
        }
        try checkFfiError(err, context: "Parse pairing file")
        guard let pf else {
            throw NSError(domain: "DeviceInstaller", code: 3, userInfo: [NSLocalizedDescriptionKey: "Null pairing file handle"])
        }
        return pf
    }

    private nonisolated static func makeTcpProvider(pairingData: Data, vpnIP: String) throws -> OpaquePointer {
        let pairingFile = try makePairingFile(from: pairingData)

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
        try checkFfiError(provErr, context: "Create TCP provider")
        guard let provider else {
            throw NSError(domain: "DeviceInstaller", code: 5, userInfo: [NSLocalizedDescriptionKey: "Null TCP provider"])
        }
        return provider
    }

    private nonisolated static func uploadAndInstall(
        afc: OpaquePointer,
        ipaPath: String,
        remoteFileName: String,
        connectInstProxy: () throws -> OpaquePointer,
        onProgress: @escaping (String) -> Void
    ) throws {
        if let dirErr = afc_make_directory(afc, "PublicStaging") {
            idevice_error_free(dirErr)
        }

        let stagingPath = "PublicStaging/\(remoteFileName)"
        var fileHandle: OpaquePointer?
        try checkFfiError(afc_file_open(afc, stagingPath, AfcWr, &fileHandle), context: "AFC open file")
        guard let fileHandle else {
            throw NSError(domain: "DeviceInstaller", code: 7, userInfo: [NSLocalizedDescriptionKey: "Null AFC file handle"])
        }

        do {
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
        } catch {
            _ = afc_file_close(fileHandle)
            throw error
        }

        if let closeErr = afc_file_close(fileHandle) {
            idevice_error_free(closeErr)
        }

        // Connect installation_proxy after AFC file is closed
        onProgress("Starting iOS installation...")
        let instClient = try connectInstProxy()
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

    private nonisolated static func performLockdownInstall(
        ipaPath: String,
        pairingData: Data,
        vpnIP: String,
        remoteFileName: String,
        onProgress: @escaping (String) -> Void
    ) throws {
        // 1. Verify lockdownd TCP + StartSession first for clear diagnostics
        onProgress("Connecting to lockdownd (\(vpnIP))...")
        do {
            let lockProv = try makeTcpProvider(pairingData: pairingData, vpnIP: vpnIP)
            defer { idevice_provider_free(lockProv) }

            var lockClient: OpaquePointer?
            try checkFfiError(lockdownd_connect(lockProv, &lockClient), context: "Lockdown connect")
            guard let lockClient else {
                throw NSError(domain: "DeviceInstaller", code: 5, userInfo: [NSLocalizedDescriptionKey: "Null lockdown client"])
            }
            defer { lockdownd_client_free(lockClient) }

            let pf = try makePairingFile(from: pairingData)
            defer { idevice_pairing_file_free(pf) }
            try checkFfiError(lockdownd_start_session(lockClient, pf), context: "Lockdown session")
        }

        // 2. Start heartbeat so iOS keeps wireless service connections alive
        onProgress("Starting heartbeat...")
        let hbProv = try makeTcpProvider(pairingData: pairingData, vpnIP: vpnIP)
        var hbClient: OpaquePointer?
        let hbErr = heartbeat_connect(hbProv, &hbClient)
        idevice_provider_free(hbProv)
        try checkFfiError(hbErr, context: "Heartbeat connect")
        guard let hbClient else {
            throw NSError(domain: "DeviceInstaller", code: 5, userInfo: [NSLocalizedDescriptionKey: "Null heartbeat client"])
        }
        let heartbeat = HeartbeatKeeper(client: hbClient)
        defer { heartbeat.stop() }
        Thread.sleep(forTimeInterval: 0.15)

        // 3. Connect AFC with a fresh TCP provider
        onProgress("Connecting AFC...")
        let afcProv = try makeTcpProvider(pairingData: pairingData, vpnIP: vpnIP)
        var afc: OpaquePointer?
        let afcErr = afc_client_connect(afcProv, &afc)
        idevice_provider_free(afcProv)
        try checkFfiError(afcErr, context: "AFC connect")
        guard let afc else {
            throw NSError(domain: "DeviceInstaller", code: 6, userInfo: [NSLocalizedDescriptionKey: "Null AFC client"])
        }
        var afcFreed = false
        defer { if !afcFreed { afc_client_free(afc) } }

        try uploadAndInstall(
            afc: afc,
            ipaPath: ipaPath,
            remoteFileName: remoteFileName,
            connectInstProxy: {
                afc_client_free(afc)
                afcFreed = true

                let instProv = try makeTcpProvider(pairingData: pairingData, vpnIP: vpnIP)
                var instClient: OpaquePointer?
                let instErr = installation_proxy_connect(instProv, &instClient)
                idevice_provider_free(instProv)
                try checkFfiError(instErr, context: "Installation proxy connect")
                guard let instClient else {
                    throw NSError(domain: "DeviceInstaller", code: 8, userInfo: [NSLocalizedDescriptionKey: "Null installation proxy"])
                }
                return instClient
            },
            onProgress: onProgress
        )
    }

    private nonisolated static func performRPPairingInstall(
        ipaPath: String,
        pairingData: Data,
        vpnIP: String,
        port: UInt16,
        remoteFileName: String,
        onProgress: @escaping (String) -> Void
    ) throws {
        onProgress("Connecting RemotePairing (\(vpnIP):\(port))...")
        var rpf: OpaquePointer?
        let rpErr = pairingData.withUnsafeBytes { buf -> UnsafeMutablePointer<IdeviceFfiError>? in
            guard let base = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            return rp_pairing_file_from_bytes(base, UInt(pairingData.count), &rpf)
        }
        try checkFfiError(rpErr, context: "Parse RemotePairing file")
        guard let rpf else {
            throw NSError(domain: "DeviceInstaller", code: 3, userInfo: [NSLocalizedDescriptionKey: "Null RemotePairing handle"])
        }
        defer { rp_pairing_file_free(rpf) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, vpnIP, &addr.sin_addr) == 1 else {
            throw NSError(domain: "DeviceInstaller", code: 4, userInfo: [NSLocalizedDescriptionKey: "Invalid VPN IP: \(vpnIP)"])
        }

        var adapter: OpaquePointer?
        var handshake: OpaquePointer?
        let tunErr = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                tunnel_create_rppairing(
                    sockPtr,
                    idevice_socklen_t(MemoryLayout<sockaddr_in>.size),
                    "Signed",
                    rpf,
                    nil,
                    nil,
                    &adapter,
                    &handshake
                )
            }
        }
        try checkFfiError(tunErr, context: "RemotePairing tunnel")
        guard let adapter, let handshake else {
            throw NSError(domain: "DeviceInstaller", code: 5, userInfo: [NSLocalizedDescriptionKey: "Null RemotePairing adapter/handshake"])
        }
        defer {
            rsd_handshake_free(handshake)
            adapter_free(adapter)
        }

        onProgress("Starting heartbeat...")
        var hbClient: OpaquePointer?
        try checkFfiError(heartbeat_connect_rsd(adapter, handshake, &hbClient), context: "Heartbeat RSD connect")
        guard let hbClient else {
            throw NSError(domain: "DeviceInstaller", code: 5, userInfo: [NSLocalizedDescriptionKey: "Null heartbeat client"])
        }
        let heartbeat = HeartbeatKeeper(client: hbClient)
        defer { heartbeat.stop() }
        Thread.sleep(forTimeInterval: 0.15)

        onProgress("Connecting AFC...")
        var afc: OpaquePointer?
        try checkFfiError(afc_client_connect_rsd(adapter, handshake, &afc), context: "AFC RSD connect")
        guard let afc else {
            throw NSError(domain: "DeviceInstaller", code: 6, userInfo: [NSLocalizedDescriptionKey: "Null AFC client"])
        }
        var afcFreed = false
        defer { if !afcFreed { afc_client_free(afc) } }

        try uploadAndInstall(
            afc: afc,
            ipaPath: ipaPath,
            remoteFileName: remoteFileName,
            connectInstProxy: {
                afc_client_free(afc)
                afcFreed = true

                var instClient: OpaquePointer?
                try checkFfiError(installation_proxy_connect_rsd(adapter, handshake, &instClient), context: "Installation proxy RSD connect")
                guard let instClient else {
                    throw NSError(domain: "DeviceInstaller", code: 8, userInfo: [NSLocalizedDescriptionKey: "Null installation proxy"])
                }
                return instClient
            },
            onProgress: onProgress
        )
    }
}
