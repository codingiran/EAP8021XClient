import Foundation
import Security

/*
 https://github.com/snowhaze/SnowHaze-iOS/blob/e434f8aa0952d6f07e8e29a722728af73f235e9d/SnowHaze/KeyManager.swift#L76
 https://github.com/openziti/ziti-sdk-swift/blob/53272de759f3001630e4b06aea66d34fb948fe4d/lib/ZitiKeychain.swift#L337
 https://github.com/geteduroam/macos-app/blob/19af1bb2cfb00ddac3ce099b7744f3400fb5972f/geteduroam/ViewController.swift#L83
 */

// MARK: - Add Certificate

public enum KeychainManager {
    /// 将证书添加到 KeyChain
    /// - Parameters:
    ///   - cerContent: 证书内容
    ///   - cerPath: 证书路径
    ///   - teamId: 开发者团队 ID
    /// - Returns: 证书
    @discardableResult
    public static func addCertificate(cerContent: String?, cerPath: String?, teamId: String?) throws -> (cer: SecCertificate, label: String) {
        guard let base64 = certificateBase64(cerContent: cerContent, cerPath: cerPath) else {
            throw EAPConfiguratorError.failedToParsePemFile
        }
        return try createCertificate(from: base64, teamId: teamId)
    }

    /// 从证书中获取 Base64 内容
    /// - Parameters:
    ///   - cerContent: 证书内容
    ///   - cerPath: 证书路径
    /// - Returns: Base64 内容
    public static func certificateBase64(cerContent: String?, cerPath: String?) -> String? {
        let pem: String? = {
            if let cerContent, !cerContent.isEmpty {
                return cerContent
            }
            if let cerPath {
                return try? String(contentsOfFile: cerPath)
            }
            return nil
        }()
        guard let pem, !pem.isEmpty else { return nil }
        // 截取 pem 内的 base64 内容
        let base64 = pem
            .components(separatedBy: "-----BEGIN CERTIFICATE-----")
            .last
            .flatMap { $0.components(separatedBy: "-----END CERTIFICATE-----").first }
            .map { $0.replacingOccurrences(of: "\n", with: "") }
        return base64
    }

    /// 从证书中获取 Base64 Data
    /// - Parameters:
    ///   - cerContent: 证书内容
    ///   - cerPath: 证书路径
    /// - Returns: Base64 Data
    public static func certificateBase64Data(cerContent: String?, cerPath: String?) -> Data? {
        guard let pemBase64 = certificateBase64(cerContent: cerContent, cerPath: cerPath) else {
            return nil
        }
        let data = Data(base64Encoded: pemBase64)
        return data
    }

    /// 创建证书
    /// - Parameters:
    ///   - pemBase64: Base64 证书内容
    ///   - teamId: 开发者团队 ID
    /// - Returns: 证书
    public static func createCertificate(from pemBase64: String, teamId: String?) throws -> (cer: SecCertificate, label: String) {
        guard let data = Data(base64Encoded: pemBase64) else {
            throw EAPConfiguratorError.failedToBase64DecodeCertificate
        }
        guard let certificateRef = SecCertificateCreateWithData(kCFAllocatorDefault, data as CFData) else {
            throw EAPConfiguratorError.failedToCreateCertificateFromData
        }
        let label = try label(for: certificateRef)

        var addquery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificateRef,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: kCFBooleanTrue!,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        if let teamId {
            addquery[kSecAttrAccessGroup as String] = "\(teamId).com.apple.networkextensionsharing"
        }

        var item: CFTypeRef?
        let status = SecItemAdd(addquery as CFDictionary, &item)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            let errStr = SecCopyErrorMessageString(status, nil) as String? ?? "\(status)"
            throw EAPConfiguratorError.failedSecItemAdd(status, errStr, label: label)
        }
        addquery = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        item = nil
        guard SecItemCopyMatching(addquery as CFDictionary, &item) == errSecSuccess, let item else {
            let errStr = SecCopyErrorMessageString(status, nil) as String? ?? "\(status)"
            throw EAPConfiguratorError.failedSecItemAdd(status, errStr, label: label)
        }
        return (item as! SecCertificate, label)
    }

    /// 从证书中获取标签
    /// - Parameter certificateRef: 证书
    /// - Returns: 标签
    public static func label(for certificateRef: SecCertificate) throws -> String {
        var commonNameRef: CFString?
        let status: OSStatus = SecCertificateCopyCommonName(certificateRef, &commonNameRef)
        if status == errSecSuccess {
            return commonNameRef! as String
        }
        guard let rawSubject = SecCertificateCopyNormalizedSubjectSequence(certificateRef) as? Data else {
            throw EAPConfiguratorError.failedToCopyCommonNameOrSubjectSequence
        }
        return rawSubject.base64EncodedString(options: [])
    }

    /// 从钥匙串中获取证书 Identity
    /// - Parameter label: 证书标签
    /// - Returns: 证书 Identity
    public static func getIdentityFromKeychain(label: String, kind: String? = nil) throws -> SecIdentity? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let kind {
            query[kSecAttrDescription as String] = kind
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            throw EAPConfiguratorError.failedSecItemCopyMatching(status)
        }
        return (item as! SecIdentity)
    }
}

#if os(macOS)

#if SPM_EAP8021X_ENABLED

import EAP8021XClientObjc

#endif

// MARK: Trust Certificate

public extension KeychainManager {
    /// 设置证书信任
    /// - Parameters:
    ///   - certificate: 证书
    ///   - domain: 信任域
    ///   - trustSettingsResult: 信任结果
    @available(macOS 10.15, *)
    @available(iOS, unavailable)
    static func trustCertificate(_ certificate: SecCertificate,
                                 _ domain: SecTrustSettingsDomain = .user,
                                 _ trustSettingsResult: SecTrustSettingsResult = .trustAsRoot) throws
    {
        let trustSettings = [
            kSecTrustSettingsResult: NSNumber(value: trustSettingsResult.rawValue),
        ] as CFTypeRef

        let trustStatus = SecTrustSettingsSetTrustSettings(certificate, domain, trustSettings)
        guard trustStatus == errSecSuccess else {
            throw EAPConfiguratorError.failedToTrustCertificate(trustStatus)
        }
    }

    /// 校验证书，是否在钥匙串中且被信任
    /// - Parameters:
    ///   - cerContent: 证书内容
    ///   - cerPath: 证书路径
    ///   - domain: 信任域
    /// - Returns: 是否在钥匙串中且被信任
    static func verifyCertificate(cerContent: String?,
                                  cerPath: String?,
                                  domain: SecTrustSettingsDomain = .user) -> Bool
    {
        // 获取 label
        guard let base64 = certificateBase64(cerContent: cerContent, cerPath: cerPath),
              let data = Data(base64Encoded: base64),
              let certificateRef = SecCertificateCreateWithData(kCFAllocatorDefault, data as CFData),
              let label = try? label(for: certificateRef)
        else {
            return false
        }
        // 判断证书是否在钥匙串中
        let query: [CFString: Any] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: label,
            kSecReturnRef: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let item
        else {
            return false
        }
        // 判断 certificate 是否受信任
        var trustSettings: CFArray?
        let status = SecTrustSettingsCopyTrustSettings((item as! SecCertificate), domain, &trustSettings)
        return status == errSecSuccess
    }
}

// MARK: - Save and fetch EAP Credentials

public extension KeychainManager {
    @available(macOS 10.15, *)
    @available(iOS, unavailable)
    static func saveEAPCredentials(username: String,
                                   password: String,
                                   ssid: String,
                                   kind: String = "802.1x Password",
                                   comment: String? = nil,
                                   useSystemKeychain: Bool = false,
                                   allAppsAccess: Bool = false) throws
    {
        let label = ssid
        let account = username
        let service = "com.apple.network.eap.user.item.wlan.ssid.\(ssid)" // 指定的 Where 值
        var systemKeychain: SecKeychain?
        if useSystemKeychain {
            // 获取 System Keychain 的引用
            // https://github.com/joshua-d-miller/macOSLAPS/blob/9c4046f5a6f019229cf560d19656c521cc059adf/macOSLAPS/Extensions/KeychainService.swift#L22
            let systemKeychainPath = "/Library/Keychains/System.keychain"
            if SecKeychainOpen(systemKeychainPath, &systemKeychain) != errSecSuccess ||
                SecKeychainUnlock(systemKeychain, 0, nil, false) != errSecSuccess
            {
                systemKeychain = nil
            }
        }

        // 删除旧的 Keychain 项（如果存在）
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrLabel as String: label,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrDescription as String: kind,
        ]
        if useSystemKeychain, let systemKeychain {
            query[kSecUseKeychain as String] = systemKeychain
        }
        if SecItemDelete(query as CFDictionary) != errSecSuccess {
            debugPrint("Failed to delete old item.")
        }

        // 配置 Access Control
        var accessRef: SecAccess?
        if allAppsAccess {
            let accessCreateStatus = SecAccessCreateForAllApplications(descriptor: "" as CFString, accessRef: &accessRef)
            if accessCreateStatus != errSecSuccess {
                accessRef = nil
            }
        } else {
            var trustedApps = [SecTrustedApplication]()
            var trustedAppRef: SecTrustedApplication?

            // https://github.com/appleopen/eap8021x/blob/0874da7abfb50ef67186cf048cd833e0f8f43b1b/EAP8021X.fproj/EAPKeychainUtil.c#L966
            let airPortApplicationGroup = "AirPort"
            if SecTrustedApplicationCreateApplicationGroup(airPortApplicationGroup.cString(using: .utf8), nil, &trustedAppRef) == errSecSuccess, let trustedApp = trustedAppRef {
                trustedApps.append(trustedApp)
                trustedAppRef = nil
            }

            if SecTrustedApplicationCreateFromPath(nil, &trustedAppRef) == errSecSuccess, let trustedApp = trustedAppRef {
                // App Self
                trustedApps.append(trustedApp)
                trustedAppRef = nil
            }

            let trustedAppsPaths = [
                "/System/Library/SystemConfiguration/EAPOLController.bundle/Contents/Resources/eapolclient",
                "/usr/libexec/airportd",
                "/System/Library/CoreServices/SystemUIServer.app",
                "/System/Library/CoreServices/WiFiAgent.app",
            ]
            for trustedAppPath in trustedAppsPaths {
                if FileManager.default.fileExists(atPath: trustedAppPath),
                   SecTrustedApplicationCreateFromPath(trustedAppPath, &trustedAppRef) == errSecSuccess,
                   let trustedApp = trustedAppRef
                {
                    trustedApps.append(trustedApp)
                    trustedAppRef = nil
                }
            }
            let result = SecAccessCreate(label as CFString, trustedApps as CFArray, &accessRef)
            if result != errSecSuccess {
                accessRef = nil
            }
        }

        // 添加新的 Keychain 项
        var insertQuery: [String: Any] = [
            kSecValueData as String: password.data(using: .utf8) ?? Data(),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        if let comment {
            insertQuery[kSecAttrComment as String] = comment
        }
        query.merge(insertQuery) { $1 }
        if let accessRef {
            query[kSecAttrAccess as String] = accessRef
        }

        // https://www.osstatus.com/ 查询 osstatus 翻译
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw EAPConfiguratorError.failedToSaveEapCredentials(status)
        }
    }

    // https://stackoverflow.com/a/61702736
    @available(macOS 10.15, *)
    @available(iOS, unavailable)
    static func SecAccessCreateForAllApplications(descriptor: CFString, accessRef outerAccessRef: UnsafeMutablePointer<SecAccess?>) -> OSStatus {
        var accessRef: SecAccess?

        // Create an access object with access granted to no application (2nd parameter).
        // It comes configured with 3 default ACLs.
        let accessCreateStatus = SecAccessCreate(descriptor, [] as CFArray, &accessRef)

        guard accessCreateStatus == errSecSuccess else { return accessCreateStatus }
        guard let access = accessRef else { return accessCreateStatus }

        // Extract the default ACLs from the created access object for the *decrypt* authorization tag.
        guard let aclList = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt) as? [SecACL] else { return errSecInvalidACL }

        // There should be exactly one ACL for the *decrypt* authorization tag.
        guard aclList.count == 1 else { return errSecInvalidACL }
        guard let decryptACL = aclList.first else { return errSecInvalidACL }

        // Extract all authorizations from the default ACL for the *decrypt* authorization tag.
        let allAuthorizations = SecACLCopyAuthorizations(decryptACL)

        // Remove the default ACL for the *decrypt* authorization tag from the access object.
        let aclRemoveStatus = SecACLRemove(decryptACL)

        guard aclRemoveStatus == errSecSuccess else { return aclRemoveStatus }

        // Create a new ACL with access for all applications and add it to the access object.
        var newDecryptACLRef: SecACL?
        let aclCreateStatus = SecACLCreateWithSimpleContents(access,
                                                             nil, // All applications have access
                                                             descriptor,
                                                             [], // Empty prompt selector
                                                             &newDecryptACLRef)

        guard aclCreateStatus == errSecSuccess else { return aclCreateStatus }
        guard let newDecryptACL = newDecryptACLRef else { return aclCreateStatus }

        // Set the authorizations extracted from the default ACL to the newly created ACL.
        let aclUpdateAuthorizationStatus = SecACLUpdateAuthorizations(newDecryptACL, allAuthorizations)

        guard aclUpdateAuthorizationStatus == errSecSuccess else { return aclUpdateAuthorizationStatus }

        // Finally, write the access to the outer pointer.
        outerAccessRef.initialize(to: access)

        return errSecSuccess
    }
}

#endif

// MARK: - Error Handing

public extension KeychainManager {
    enum EAPConfiguratorError: LocalizedError {
        /// Unable parse pem file
        case failedToParsePemFile

        /// Unable to add certificate to keychain
        case failedSecItemAdd(OSStatus, String, label: String? = nil)

        /// Unable to copy from keychain
        case failedSecItemCopyMatching(OSStatus)

        /// Unable to decode certificate dat
        case failedToBase64DecodeCertificate

        /// Unable to create certificate from data
        case failedToCreateCertificateFromData

        /// Unable to get common name or subject sequence f from certificate
        case failedToCopyCommonNameOrSubjectSequence

        /// Unable to fetch identity
        case failedToFetchIdentity(OSStatus, String)

        /// Unable to trust certificate
        case failedToTrustCertificate(OSStatus)

        /// Unable to save eap credentials
        case failedToSaveEapCredentials(OSStatus)

        public var errorDescription: String? {
            switch self {
            case .failedToParsePemFile:
                return "Unable to parse pem file"
            case .failedSecItemAdd(let oSStatus, let string, let label):
                return "Unable to add certificate to keychain: \(oSStatus) - \(string) - \(label ?? "")"
            case .failedSecItemCopyMatching(let oSStatus):
                return "Unable to copy from keychain: \(oSStatus)"
            case .failedToBase64DecodeCertificate:
                return "Unable to decode certificate data"
            case .failedToCreateCertificateFromData:
                return "Unable to create certificate from data"
            case .failedToCopyCommonNameOrSubjectSequence:
                return "Unable to get common name or subject sequence from certificate"
            case .failedToFetchIdentity(let oSStatus, let string):
                return "Unable to fetch identity: \(oSStatus) - \(string)"
            case .failedToTrustCertificate(let oSStatus):
                return "Unable to trust certificate: \(oSStatus)"
            case .failedToSaveEapCredentials(let oSStatus):
                return "Unable to save eap credentials: \(oSStatus)"
            }
        }
    }
}
