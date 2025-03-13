//
//  EAP8021xProfile.swift
//  EAP8021XClient
//
//  Created by CodingIran on 2025/3/13.
//

import Foundation

#if os(macOS)

#if SPM_EAP8021X_ENABLED

@_exported import EAP8021XClientObjc

/// EAP Type
public enum EAP8021xEAPType: Int, Codable, Sendable, CustomStringConvertible {
    case invalid = 0
    case identity = 1
    case notification = 2
    case nak = 3
    case md5Challenge = 4
    case oneTimePassword = 5
    case genericTokenCard = 6
    case tls = 13
    case ciscoLEAP = 17
    case eapsim = 18
    case srpsha1 = 19
    case ttls = 21
    case eapaka = 23
    case peap = 25
    case mschapv2 = 26
    case extensions = 33
    case eapfast = 43
    case eapakaPrime = 50

    public var description: String {
        switch self {
        case .invalid: return "Invalid"
        case .identity: return "Identity"
        case .notification: return "Notification"
        case .nak: return "Nak"
        case .md5Challenge: return "MD5-Challenge"
        case .oneTimePassword: return "One-Time Password"
        case .genericTokenCard: return "Generic Token Card"
        case .tls: return "TLS"
        case .ciscoLEAP: return "Cisco LEAP"
        case .eapsim: return "EAP-SIM"
        case .srpsha1: return "SRP-SHA1"
        case .ttls: return "TTLS"
        case .eapaka: return "EAP-AKA"
        case .peap: return "PEAP"
        case .mschapv2: return "MSCHAPv2"
        case .extensions: return "Extensions"
        case .eapfast: return "EAP-FAST"
        case .eapakaPrime: return "EAP-AKA'"
        }
    }

    fileprivate init(objc: NSNumber) {
        let type = EAP8021xEAPType(rawValue: objc.intValue)
        self = type ?? .invalid
    }

    fileprivate func toObjc() -> NSNumber {
        NSNumber(value: rawValue)
    }
}

/// Security type
public enum EAP8021xSecurityType: Int, Codable, Sendable, CustomStringConvertible {
    case unknown = 0
    case wep
    case wpa
    case wpa2
    case any

    public var description: String {
        switch self {
        case .unknown: return "Unknown"
        case .wep: return "WEP"
        case .wpa: return "WPA"
        case .wpa2: return "WPA2"
        case .any: return "Any"
        }
    }

    fileprivate init(objc: EAP8021XClientObjc.EAP8021xSecurityType) {
        let type = EAP8021xSecurityType(rawValue: objc.rawValue)
        self = type ?? .unknown
    }

    func toObjc() -> EAP8021XClientObjc.EAP8021xSecurityType {
        EAP8021XClientObjc.EAP8021xSecurityType(rawValue: rawValue) ?? .unknown
    }
}

/// Inner authentication type
public enum EAP8021TTLSInnerAuthType: Int, Codable, Sendable, CustomStringConvertible {
    case unknown = 0
    case pap
    case chap
    case mschap
    case mschapv2

    public var description: String {
        switch self {
        case .unknown: return "Unknown"
        case .pap: return "PAP"
        case .chap: return "CHAP"
        case .mschap: return "MSCHAP"
        case .mschapv2: return "MSCHAPv2"
        }
    }

    fileprivate init(objc: EAP8021XClientObjc.EAP8021TTLSInnerAuthType) {
        let type = EAP8021TTLSInnerAuthType(rawValue: objc.rawValue)
        self = type ?? .unknown
    }

    func toObjc() -> EAP8021XClientObjc.EAP8021TTLSInnerAuthType {
        EAP8021XClientObjc.EAP8021TTLSInnerAuthType(rawValue: rawValue) ?? .unknown
    }
}

/// EAP8021x Profile
public struct EAP8021xProfile: Codable, Sendable {
    /// Profile ID
    public var profileId: String?

    /// SSID
    public var ssid: String?

    /// User defined name
    public var userDefinedName: String?

    /// Domain name
    public var domainName: String?

    /// Outer identity
    public var outerIdentity: String?

    /// Accept EAP types
    public var acceptEAPTypes: [EAP8021xEAPType]?

    /// Security type
    public var securityType: EAP8021xSecurityType = .unknown

    /// Inner authentication type
    public var ttlsInnerAuthType: EAP8021TTLSInnerAuthType = .unknown

    /// Trusted server name
    public var trustedServerName: [String]?

    /// Trusted certificate
    public var trustedCertificate: [Data]?
}

extension EAP8021xProfile {
    init(objc: EAP8021XClientObjc.EAP8021xProfile) {
        self.init(profileId: objc.profileId,
                  ssid: objc.ssid,
                  userDefinedName: objc.userDefinedName,
                  domainName: objc.domainName,
                  outerIdentity: objc.outerIdentity,
                  acceptEAPTypes: objc.acceptEAPTypes?.map { EAP8021xEAPType(objc: $0) },
                  securityType: EAP8021xSecurityType(objc: objc.securityType),
                  ttlsInnerAuthType: EAP8021TTLSInnerAuthType(objc: objc.ttlsInnerAuthType),
                  trustedServerName: objc.trustedServerName,
                  trustedCertificate: objc.trustedCertificate)
    }

    func toObjc() -> EAP8021XClientObjc.EAP8021xProfile {
        let profileObjc = EAP8021XClientObjc.EAP8021xProfile()
        profileObjc.profileId = profileId
        profileObjc.ssid = ssid
        profileObjc.userDefinedName = userDefinedName
        profileObjc.domainName = domainName
        profileObjc.outerIdentity = outerIdentity
        profileObjc.acceptEAPTypes = acceptEAPTypes?.map { $0.toObjc() }
        profileObjc.securityType = securityType.toObjc()
        profileObjc.ttlsInnerAuthType = ttlsInnerAuthType.toObjc()
        profileObjc.trustedServerName = trustedServerName
        profileObjc.trustedCertificate = trustedCertificate
        return profileObjc
    }
}

#endif

#endif
