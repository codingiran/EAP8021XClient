import Foundation

// Enforce minimum Swift version for all platforms and build systems.
#if swift(<5.5)
#error("EAP8021XClient doesn't support Swift versions below 5.5.")
#endif

/// Current EAP8021XClient version 0.2.0. Necessary since SPM doesn't use dynamic libraries. Plus this will be more accurate.
let version = "0.2.0"

public enum EAP8021XClient {}

// MARK: - Certificate

public extension EAP8021XClient {
    static func importCACertificate(_ certContent: String?, certPath: String?, teamId: String? = nil) throws {
#if os(macOS)
        let certificate = try KeychainManager.addCertificate(cerContent: certContent, cerPath: certPath, teamId: teamId)
        try KeychainManager.trustCertificate(certificate.cer, .user, .trustRoot)
#else
        try KeychainManager.addCertificate(cerContent: certContent, cerPath: certPath, teamId: teamId)
#endif
    }

    static func importServerCertificate(_ certContent: String?, certPath: String?, teamId: String? = nil) throws {
#if os(macOS)
        let certificate = try KeychainManager.addCertificate(cerContent: certContent, cerPath: certPath, teamId: teamId)
        try KeychainManager.trustCertificate(certificate.cer, .user, .trustAsRoot)
#else
        try KeychainManager.addCertificate(cerContent: certContent, cerPath: certPath, teamId: teamId)
#endif
    }

#if os(macOS)
    static func isCertificateTrusted(_ certContent: String?, certPath: String?) -> Bool {
        let isTrusted = KeychainManager.verifyCertificate(cerContent: certContent, cerPath: certPath)
        return isTrusted
    }
#endif
}

#if os(macOS)

// MARK: - EAPCredentials

public extension EAP8021XClient {
    static func saveEAPCredentials(username: String,
                                   password: String,
                                   ssid: String,
                                   kind: String = "802.1x Password",
                                   comment: String? = nil,
                                   useSystemKeychain: Bool = false,
                                   allAppsAccess: Bool = false) throws
    {
        try KeychainManager.saveEAPCredentials(username: username,
                                               password: password,
                                               ssid: ssid,
                                               kind: kind,
                                               comment: comment,
                                               useSystemKeychain: useSystemKeychain,
                                               allAppsAccess: allAppsAccess)
    }
}

// MARK: - EAPProfile

#if SPM_EAP8021X_ENABLED

import EAP8021XClientObjc

#endif

public extension EAP8021XClient {
    static func listAllProfiles() -> [Eap8021xProfile]? {
        Eap8021x.listProfiles()
    }

    static func profileWithSSID(_ ssid: String) -> Eap8021xProfile? {
        Eap8021x.profile(withSSID: ssid)
    }

    static func createProfile(_ eap8021xProfile: Eap8021xProfile) -> Bool {
        Eap8021x.createProfile(with: eap8021xProfile)
    }

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

    @discardableResult
    static func removeProfileWithSSID(_ ssid: String) -> Bool {
        Eap8021x.removeProfile(withSSID: ssid)
    }

    @discardableResult
    static func removeProfileWithId(_ profileId: String) -> Bool {
        Eap8021x.removeProfile(withId: profileId)
    }

    @discardableResult
    static func removeProfile(_ eap8021xProfile: Eap8021xProfile) -> Bool {
        Eap8021x.remove(eap8021xProfile)
    }
}

#endif
