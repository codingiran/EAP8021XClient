import Foundation

// Enforce minimum Swift version for all platforms and build systems.
#if swift(<5.5)
#error("EAP8021XClient doesn't support Swift versions below 5.5.")
#endif

/// Current EAP8021XClient version 0.3.0. Necessary since SPM doesn't use dynamic libraries. Plus this will be more accurate.
let version = "0.3.0"

public enum EAP8021XClient {}

// MARK: - Certificate

public extension EAP8021XClient {
    /// 导入 CA 证书
    /// - Parameters:
    ///   - certContent: 证书内容
    ///   - certPath: 证书路径
    ///   - teamId: 团队 ID
    static func importCACertificate(_ certContent: String?, certPath: String?, teamId: String? = nil) throws {
#if os(macOS)
        let certificate = try KeychainManager.addCertificate(cerContent: certContent, cerPath: certPath, teamId: teamId)
        try KeychainManager.trustCertificate(certificate.cer, .user, .trustRoot)
#else
        try KeychainManager.addCertificate(cerContent: certContent, cerPath: certPath, teamId: teamId)
#endif
    }

    /// 导入服务器证书
    /// - Parameters:
    ///   - certContent: 证书内容
    ///   - certPath: 证书路径
    ///   - teamId: 团队 ID
    static func importServerCertificate(_ certContent: String?, certPath: String?, teamId: String? = nil) throws {
#if os(macOS)
        let certificate = try KeychainManager.addCertificate(cerContent: certContent, cerPath: certPath, teamId: teamId)
        try KeychainManager.trustCertificate(certificate.cer, .user, .trustAsRoot)
#else
        try KeychainManager.addCertificate(cerContent: certContent, cerPath: certPath, teamId: teamId)
#endif
    }

#if os(macOS)
    /// 验证证书是否可信
    /// - Parameters:
    ///   - certContent: 证书内容
    ///   - certPath: 证书路径
    static func isCertificateTrusted(_ certContent: String?, certPath: String?) -> Bool {
        let isTrusted = KeychainManager.verifyCertificate(cerContent: certContent, cerPath: certPath)
        return isTrusted
    }
#endif
}

// MARK: - EAPCredentials

public extension EAP8021XClient {
    /// 保存 EAP 凭证
    /// - Parameters:
    ///   - ssid: SSID
    ///   - username: 用户名
    ///   - password: 密码
    ///   - kind: 凭证类型
    ///   - service: 服务名
    ///   - comment: 备注
    ///   - allAppsAccess: 是否允许所有应用访问
    ///   - useSystemKeychain: 是否使用 System Keychain
    static func saveEAPCredential(ssid: String,
                                  username: String,
                                  password: String,
                                  kind: String?,
                                  service: String?,
                                  comment: String? = nil,
                                  allAppsAccess: Bool = false,
                                  useSystemKeychain: Bool = false) throws
    {
        let accessControl: KeychainManager.AcceessControl? = {
#if os(macOS)
            if allAppsAccess {
                return .all
            } else {
                return .specific(trustedApps: [
                    "/System/Library/SystemConfiguration/EAPOLController.bundle/Contents/Resources/eapolclient",
                    "/usr/libexec/airportd",
                    "/System/Library/CoreServices/SystemUIServer.app",
                    "/System/Library/CoreServices/WiFiAgent.app",
                ], trustedAppGoups: [
                    "AirPort",
                ], includeSelf: true)
            }
#else
            return nil
#endif
        }()
        let credential = KeychainManager.EAPCredential(ssid: ssid,
                                                       username: username,
                                                       password: password,
                                                       kind: kind,
                                                       comment: comment,
                                                       service: service,
                                                       accessControl: accessControl)
        try saveEAPCredential(credential, useSystemKeychain: useSystemKeychain)
    }

    /// 保存 EAP 凭证
    /// - Parameters:
    ///   - credential: EAP 凭证
    ///   - useSystemKeychain: 是否使用 System Keychain
    static func saveEAPCredential(_ credential: KeychainManager.EAPCredential, useSystemKeychain: Bool = false) throws {
        try KeychainManager.saveEAPCredential(credential, useSystemKeychain: useSystemKeychain)
    }

    /// 获取单个 EAP 凭证
    /// - Parameters:
    ///   - ssid: SSID
    ///   - kind: 凭证类型
    ///   - username: 用户名
    ///   - returnData: 是否返回数据
    /// - Returns: EAP 凭证
    static func getEAPCredential(ssid: String?,
                                 kind: String? = nil,
                                 username: String? = nil,
                                 returnAttributes: Bool = true,
                                 returnData: Bool = true) throws -> KeychainManager.EAPCredential?
    {
        try KeychainManager.getEAPCredential(ssid: ssid,
                                             kind: kind,
                                             username: username,
                                             returnAttributes: returnAttributes,
                                             returnData: returnData)
    }

    /// 获取多个 EAP 凭证，返回的 EAPCredential 中不包含 password
    /// - Parameters:
    ///   - ssid: SSID
    ///   - kind: 凭证类型
    ///   - username: 用户名
    ///   - returnAttributes: 是否返回附加属性
    /// - Returns: EAP 凭证列表
    static func getEAPCredentials(ssid: String?,
                                  kind: String? = nil,
                                  username: String? = nil,
                                  returnAttributes: Bool = true) throws -> [KeychainManager.EAPCredential]
    {
        try KeychainManager.getEAPCredentials(ssid: ssid,
                                              kind: kind,
                                              username: username,
                                              returnAttributes: returnAttributes)
    }

    /// 删除 EAP 凭证
    /// - Parameters:
    ///   - ssid: SSID
    ///   - kind: 凭证类型
    ///   - username: 用户名
    ///   - service: 服务名
    ///   - useSystemKeychain: 是否使用 System Keychain
    static func deleteEAPCredential(ssid: String,
                                    username: String? = nil,
                                    kind: String? = nil,
                                    service: String? = nil,
                                    useSystemKeychain: Bool = false) throws
    {
        try KeychainManager.deleteEAPCredential(ssid: ssid,
                                                username: username,
                                                kind: kind,
                                                service: service,
                                                useSystemKeychain: useSystemKeychain)
    }
}

#if os(macOS)

// MARK: - EAPProfile

#if SPM_EAP8021X_ENABLED

import EAP8021XClientObjc

#endif

public extension EAP8021XClient {
    /// 获取所有 EAP 配置文件
    static func listAllProfiles() -> [Eap8021xProfile]? {
        Eap8021x.listProfiles()
    }

    /// 获取指定 SSID 的 EAP 配置文件
    /// - Parameters:
    ///   - ssid: SSID
    static func profileWithSSID(_ ssid: String) -> Eap8021xProfile? {
        Eap8021x.profile(withSSID: ssid)
    }

    /// 创建 EAP 配置文件
    /// - Parameters:
    ///   - eap8021xProfile: EAP 配置文件
    static func createProfile(_ eap8021xProfile: Eap8021xProfile) -> Bool {
        Eap8021x.createProfile(with: eap8021xProfile)
    }

    /// 创建 EAP 配置文件
    /// - Parameters:
    ///   - ssid: SSID
    ///   - acceptEAPTypes: 接受的 EAP 类型
    ///   - userDefinedName: 用户定义的名称
    ///   - domainName: 域名
    ///   - securityType: 安全类型
    ///   - outerIdentity: 外部身份
    ///   - ttlSInnerAuthentication: TTL-S 内部认证类型
    ///   - trustedServerName: 可信服务器名称
    ///   - trustedCertificate: 可信证书
    static func createProfile(ssid: String? = nil,
                              acceptEAPTypes: [Eap8021xEAPType]? = [.PEAP],
                              userDefinedName: String? = nil,
                              domainName: String? = nil,
                              securityType: Eap8021xSecurityType = .any,
                              outerIdentity: String? = nil,
                              ttlSInnerAuthentication: Eap8021TTLSInnerAuthType = .mschaPv2,
                              trustedServerName: [String]? = nil,
                              trustedCertificate: [Data]? = nil) -> Bool
    {
        Eap8021x.createProfile(withSSID: ssid,
                               acceptEAPTypes: acceptEAPTypes?.map { NSNumber(value: $0.rawValue) },
                               userDefinedName: userDefinedName,
                               domainName: domainName,
                               securityType: securityType,
                               outerIdentity: outerIdentity,
                               ttlSInnerAuthentication: ttlSInnerAuthentication,
                               trustedServerName: trustedServerName,
                               trustedCertificate: trustedCertificate)
    }

    /// 删除指定 SSID 的 EAP 配置文件
    /// - Parameters:
    ///   - ssid: SSID
    @discardableResult
    static func removeProfileWithSSID(_ ssid: String) -> Bool {
        Eap8021x.removeProfile(withSSID: ssid)
    }

    /// 删除指定 ID 的 EAP 配置文件
    /// - Parameters:
    ///   - profileId: 配置文件 ID
    @discardableResult
    static func removeProfileWithId(_ profileId: String) -> Bool {
        Eap8021x.removeProfile(withId: profileId)
    }

    /// 删除指定 EAP 配置文件
    /// - Parameters:
    ///   - eap8021xProfile: EAP 配置文件
    @discardableResult
    static func removeProfile(_ eap8021xProfile: Eap8021xProfile) -> Bool {
        Eap8021x.remove(eap8021xProfile)
    }
}

#endif
