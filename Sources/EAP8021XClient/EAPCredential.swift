//
//  EAPCredential.swift
//  EAP8021XClient
//
//  Created by CodingIran on 2025/1/7.
//

import Foundation

open class EAPCredential: Codable, NSSecureCoding {
    public enum AcceessControl: Codable {
        /// 所有应用
        case all
        /// 特定应用
        case specific(trustedApps: [String], trustedAppGoups: [String], includeSelf: Bool)
    }

    /// SSID, 可选, Keychain 的 Label
    public let ssid: String?
    /// 用户名, 可选, Keychain 的 Account
    public let username: String?
    /// 密码, 可选, Keychain 的 Value
    public let password: String?
    /// 凭证类型, 可选, Keychain 的 Description
    public var kind: String?
    /// 备注, 可选, Keychain 的 Comment
    public var comment: String?
    /// 服务
    public var service: String?
    /// 访问权限, 可选, only on macOS
    @available(macOS 10.15, *)
    public var accessControl: AcceessControl?

    public init(ssid: String? = nil,
                username: String? = nil,
                password: String? = nil,
                kind: String? = nil,
                comment: String? = nil,
                service: String? = nil,
                accessControl: AcceessControl? = nil)
    {
        self.ssid = ssid
        self.username = username
        self.password = password
        self.kind = kind
        self.comment = comment
        self.service = service
        self.accessControl = accessControl
    }

    public init(attributes: [String: Any]) {
        ssid = attributes[kSecAttrLabel as String] as? String
        username = attributes[kSecAttrAccount as String] as? String
        kind = attributes[kSecAttrDescription as String] as? String
        comment = attributes[kSecAttrComment as String] as? String
        service = attributes[kSecAttrService as String] as? String
        password = {
            guard let passwordData = attributes[kSecValueData as String] as? Data else { return nil }
            return String(data: passwordData, encoding: .utf8)
        }()
    }

    public static var supportsSecureCoding: Bool { true }

    public func encode(with coder: NSCoder) {
        coder.encode(ssid, forKey: "ssid")
        coder.encode(username, forKey: "username")
        coder.encode(password, forKey: "password")
        coder.encode(kind, forKey: "kind")
        coder.encode(comment, forKey: "comment")
        coder.encode(service, forKey: "service")
//        coder.encode(accessControl, forKey: "accessControl")
    }

    public required init?(coder: NSCoder) {
        ssid = coder.decodeObject(forKey: "ssid") as? String
        username = coder.decodeObject(forKey: "username") as? String
        password = coder.decodeObject(forKey: "password") as? String
        kind = coder.decodeObject(forKey: "kind") as? String
        comment = coder.decodeObject(forKey: "comment") as? String
        service = coder.decodeObject(forKey: "service") as? String
//        accessControl = coder.decodeObject(forKey: "accessControl") as? AcceessControl
    }
}

extension EAPCredential: CustomStringConvertible {
    public var description: String {
        "EAPCredential(ssid: \(ssid ?? "null"), username: \(username ?? "null"), password: \(password ?? "null"), kind: \(kind ?? "null"), comment: \(comment ?? "null"), service: \(service ?? "null"), accessControl: \(String(describing: accessControl))"
    }
}
