import Foundation
import Security

/*
 https://github.com/snowhaze/SnowHaze-iOS/blob/e434f8aa0952d6f07e8e29a722728af73f235e9d/SnowHaze/KeyManager.swift#L76
 https://github.com/openziti/ziti-sdk-swift/blob/53272de759f3001630e4b06aea66d34fb948fe4d/lib/ZitiKeychain.swift#L337
 https://github.com/geteduroam/macos-app/blob/19af1bb2cfb00ddac3ce099b7744f3400fb5972f/geteduroam/ViewController.swift#L83
 */

// MARK: - Add Certificate

public enum KeychainManager: Sendable {
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

@_implementationOnly import EAP8021XClientObjc

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

#endif

// MARK: - Save and fetch EAP Credentials

public extension KeychainManager {
    /// 保存 EAP 凭证
    /// - Parameters:
    ///   - credential: 凭证
    ///   - useSystemKeychain: 是否使用 System Keychain, only on macOS
    static func saveEAPCredential(_ credential: EAPCredential, useSystemKeychain: Bool = false) throws {
        try saveEAPCredential(ssid: credential.ssid,
                              username: credential.username,
                              password: credential.password,
                              kind: credential.kind,
                              service: credential.service,
                              comment: credential.comment,
                              accessControl: credential.accessControl,
                              useSystemKeychain: useSystemKeychain)
    }

    /// 保存 EAP 凭证
    /// - Parameters:
    ///   - ssid: 凭证标签, 可选
    ///   - username: 用户名, 可选
    ///   - password: 密码, 可选
    ///   - kind: 凭证类型, 可选
    ///   - service: 服务, 可选
    ///   - comment: 备注, 可选
    ///   - accessControl: 访问权限, 可选, only on macOS
    ///   - useSystemKeychain: 是否使用 System Keychain, only on macOS
    static func saveEAPCredential(ssid: String?,
                                  username: String?,
                                  password: String?,
                                  kind: String? = nil,
                                  service: String? = nil,
                                  comment: String? = nil,
                                  accessControl: EAPCredential.AcceessControl? = nil,
                                  useSystemKeychain: Bool = false) throws
    {
        let label = ssid
        guard let label else {
            throw EAPConfiguratorError.failedToSaveEAPCredentials(errSecParam, "Label is required")
        }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrLabel as String: label,
        ]
        if let username, !username.isEmpty {
            query[kSecAttrAccount as String] = username
        }
        if let kind, !kind.isEmpty {
            query[kSecAttrDescription as String] = kind
        }
        if let service, !service.isEmpty {
            query[kSecAttrService as String] = service
        }

#if os(macOS)
        if useSystemKeychain, let systemKeychain = systemKeychain() {
            query[kSecUseKeychain as String] = systemKeychain
        }
#endif
        // 删除旧的 Keychain 项
        _ = try? deleteEAPCredential(query: query)

        // 添加新的 Keychain 项
        var insertQuery: [String: Any] = [
            kSecValueData as String: password?.data(using: .utf8) ?? Data(),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        if let comment {
            insertQuery[kSecAttrComment as String] = comment
        }

#if os(macOS)
        // 配置 Access Control
        if let accessRef = accessRef(label: label, acceessControl: accessControl) {
            insertQuery[kSecAttrAccess as String] = accessRef
        }
#endif

        query.merge(insertQuery) { $1 }

        // https://www.osstatus.com/ 查询 osstatus 翻译
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw EAPConfiguratorError.failedToSaveEAPCredentials(status, nil)
        }
    }

    /// 获取单个 EAP 凭证
    /// - Parameters:
    ///   - ssid: SSID, 可选
    ///   - kind: 凭证类型, 可选
    ///   - username: 用户名, 可选
    ///   - comment: 备注, 可选
    ///   - returnAttributes: 是否返回附加属性, 默认 true
    ///   - returnData: 是否返回数据, 默认 true
    ///   - fromSystemKeychain: 是否从 System Keychain 查询, only on macOS
    /// - Returns: EAP 凭证
    static func getEAPCredential(ssid: String?,
                                 kind: String? = nil,
                                 username: String? = nil,
                                 comment: String? = nil,
                                 returnAttributes: Bool = true,
                                 returnData: Bool = true,
                                 fromSystemKeychain: Bool = false) throws -> EAPCredential?
    {
        let query = getEAPCredentialQuery(ssid: ssid,
                                          kind: kind,
                                          username: username,
                                          comment: comment,
                                          returnAttributes: returnAttributes,
                                          returnData: returnData,
                                          returnSingle: true,
                                          fromSystemKeychain: fromSystemKeychain)
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status != errSecItemNotFound else {
            return nil
        }
        guard status == errSecSuccess, let attributes = result as? [String: Any] else {
            throw EAPConfiguratorError.failedToGetEAPCredentials(status)
        }
        return EAPCredential(attributes: attributes)
    }

    /// 获取多个 EAP 凭证, 返回的 EAPCredential 中不包含 password
    /// - Parameters:
    ///   - ssid: SSID, 可选
    ///   - kind: 凭证类型, 可选
    ///   - username: 用户名, 可选
    ///   - comment: 备注, 可选
    ///   - returnAttributes: 是否返回附加属性, 默认 true
    ///   - fromSystemKeychain: 是否从 System Keychain 查询, only on macOS
    /// - Returns: EAP 凭证
    static func getEAPCredentials(ssid: String?,
                                  kind: String? = nil,
                                  username: String? = nil,
                                  comment: String? = nil,
                                  returnAttributes: Bool = true,
                                  fromSystemKeychain: Bool = false) throws -> [EAPCredential]
    {
        // 查询多个凭证，必须设置 kSecReturnData 为 false，否则查询报错
        let query = getEAPCredentialQuery(ssid: ssid,
                                          kind: kind,
                                          username: username,
                                          comment: comment,
                                          returnAttributes: returnAttributes,
                                          returnData: false,
                                          returnSingle: false,
                                          fromSystemKeychain: fromSystemKeychain)
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status != errSecItemNotFound else {
            return []
        }
        guard status == errSecSuccess, let attributesList = result as? [[String: Any]] else {
            throw EAPConfiguratorError.failedToGetEAPCredentials(status)
        }
        return attributesList.map { EAPCredential(attributes: $0) }
    }

    /// 获取 EAP 凭证查询条件
    /// - Parameters:
    ///   - ssid: SSID, 可选
    ///   - kind: 凭证类型, 可选
    ///   - username: 用户名, 可选
    ///   - comment: 备注, 可选
    ///   - returnAttributes: 是否返回附加属性, 默认 true
    ///   - returnData: 是否返回数据, 默认 true
    ///   - returnSingle: 是否返回单个凭证, 默认 true
    ///   - fromSystemKeychain: 是否从 System Keychain 查询, only on macOS
    /// - Returns: 查询条件
    private static func getEAPCredentialQuery(ssid: String?,
                                              kind: String? = nil,
                                              username: String? = nil,
                                              comment: String? = nil,
                                              returnAttributes: Bool = true,
                                              returnData: Bool = true,
                                              returnSingle: Bool = true,
                                              fromSystemKeychain: Bool = false) -> [String: Any]
    {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnData as String: returnData, // 返回数据
            kSecReturnAttributes as String: returnAttributes, // 返回附加属性（如 Label 等）
            kSecMatchLimit as String: returnSingle ? kSecMatchLimitOne : kSecMatchLimitAll, // 仅返回一个匹配项
        ]
        if let ssid, !ssid.isEmpty {
            query[kSecAttrLabel as String] = ssid
        }
        if let username, !username.isEmpty {
            query[kSecAttrAccount as String] = username
        }
        if let kind, !kind.isEmpty {
            query[kSecAttrDescription as String] = kind
        }
        if let comment, !comment.isEmpty {
            query[kSecAttrComment as String] = comment
        }
#if os(macOS)
        if fromSystemKeychain, let systemKeychain = systemKeychain() {
            query[kSecUseKeychain as String] = systemKeychain
        }
#endif
        return query
    }

    /// 删除 EAP 凭证
    /// - Parameters:
    ///   - ssid: SSID
    ///   - username: 用户名, 可选
    ///   - kind: 凭证类型, 可选
    ///   - service: 服务, 可选
    ///   - useSystemKeychain: 是否使用 System Keychain, only on macOS
    /// - Returns: 是否删除成功, 如果凭证不存在, 则返回 false
    @discardableResult
    static func deleteEAPCredential(ssid: String,
                                    username: String? = nil,
                                    kind: String? = nil,
                                    service: String? = nil,
                                    useSystemKeychain: Bool = false) throws -> Bool
    {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrLabel as String: ssid,
        ]
        if let username, !username.isEmpty {
            query[kSecAttrAccount as String] = username
        }
        if let kind, !kind.isEmpty {
            query[kSecAttrDescription as String] = kind
        }
        if let service, !service.isEmpty {
            query[kSecAttrService as String] = service
        }
#if os(macOS)
        if useSystemKeychain, let systemKeychain = systemKeychain() {
            query[kSecUseKeychain as String] = systemKeychain
        }
#endif
        return try deleteEAPCredential(query: query)
    }

    @discardableResult
    private static func deleteEAPCredential(query: [String: Any]) throws -> Bool {
        // 删除前先判断是否存在
        guard SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess else {
            // 不存在，直接返回
            return false
        }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            throw EAPConfiguratorError.failedToDeleteEAPCredentials(status)
        }
        return true
    }

#if os(macOS)
    /// 获取 System Keychain
    /// Reference: https://github.com/joshua-d-miller/macOSLAPS/blob/9c4046f5a6f019229cf560d19656c521cc059adf/macOSLAPS/Extensions/KeychainService.swift#L22
    /// - Returns: System Keychain 的引用
    private static func systemKeychain() -> SecKeychain? {
        var systemKeychain: SecKeychain?
        let systemKeychainPath = "/Library/Keychains/System.keychain"
        if SecKeychainOpen(systemKeychainPath, &systemKeychain) != errSecSuccess || SecKeychainUnlock(systemKeychain, 0, nil, false) != errSecSuccess {
            systemKeychain = nil
        }
        return systemKeychain
    }
#endif
}

// MARK: - Error Handing

public extension KeychainManager {
    enum EAPConfiguratorError: LocalizedError, Sendable {
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
        case failedToSaveEAPCredentials(OSStatus, String?)
        /// Unable to get eap credentials
        case failedToGetEAPCredentials(OSStatus)
        /// Unable to delete eap credentials
        case failedToDeleteEAPCredentials(OSStatus)

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
            case .failedToSaveEAPCredentials(let oSStatus, let string):
                var message = "\(oSStatus)"
                if let string { message += " - \(string)" }
                return "Unable to save eap credentials: \(message)"
            case .failedToGetEAPCredentials(let oSStatus):
                return "Unable to get eap credentials: \(oSStatus)"
            case .failedToDeleteEAPCredentials(let oSStatus):
                return "Unable to delete eap credentials: \(oSStatus)"
            }
        }
    }
}

// MARK: - Access Control

#if os(macOS)

extension KeychainManager {
    static func accessRef(label: String, acceessControl: EAPCredential.AcceessControl?) -> SecAccess? {
        guard let acceessControl else {
            return nil
        }
        var accessRef: SecAccess?
        switch acceessControl {
        case .all:
            let accessCreateStatus = SecAccessCreateForAllApplications(descriptor: "" as CFString, accessRef: &accessRef)
            if accessCreateStatus != errSecSuccess {
                accessRef = nil
            }
        case .specific(let trustedAppsPaths, let trustedAppGoups, let includeSelf):
            var trustedApps = [SecTrustedApplication]()
            var trustedAppRef: SecTrustedApplication?

            // App Self
            if includeSelf, SecTrustedApplicationCreateFromPath(nil, &trustedAppRef) == errSecSuccess,
               let trustedApp = trustedAppRef
            {
                // App Self
                trustedApps.append(trustedApp)
                trustedAppRef = nil
            }

            // Trusted Apps
            for trustedAppPath in trustedAppsPaths {
                if FileManager.default.fileExists(atPath: trustedAppPath),
                   SecTrustedApplicationCreateFromPath(trustedAppPath, &trustedAppRef) == errSecSuccess,
                   let trustedApp = trustedAppRef
                {
                    trustedApps.append(trustedApp)
                    trustedAppRef = nil
                }
            }

            // Trusted App Groups
            // https://github.com/appleopen/eap8021x/blob/0874da7abfb50ef67186cf048cd833e0f8f43b1b/EAP8021X.fproj/EAPKeychainUtil.c#L966
            for trustedAppGroup in trustedAppGoups {
                if EAPOLClientWrapper.secTrustedApplicationCreateApplicationGroup(trustedAppGroup.cString(using: .utf8), anchor: nil, app: &trustedAppRef) == errSecSuccess,
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
        return accessRef
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
