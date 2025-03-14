@testable import EAP8021XClient
import XCTest

final class EAP8021XClientTests: XCTestCase {
    func testExample() throws {
        // XCTest Documentation
        // https://developer.apple.com/documentation/xctest

        // Defining Test Cases and Test Methods
        // https://developer.apple.com/documentation/xctest/defining_test_cases_and_test_methods
    }

    func testSaveCredentials() throws {
        let ssid = "xxxx"
        try EAP8021XClient.saveEAPCredential(ssid: ssid,
                                             username: "xxxxxxxx",
                                             password: "xxxxx",
                                             kind: "xxxxxxxx",
                                             service: "com.apple.network.eap.user.item.wlan.ssid.\(ssid)",
                                             comment: "For xxxxxxx",
                                             allAppsAccess: false,
                                             useSystemKeychain: false)
    }

    func testFetchCredential() throws {
        let credential = try EAP8021XClient.getEAPCredential(ssid: nil, comment: "For xxxx")
        debugPrint("-------\(String(describing: credential?.description))")
    }

    func testFetchCredentials() throws {
        let credentials = try EAP8021XClient.getEAPCredentials(ssid: nil, comment: "For xxxx", returnData: true)
        debugPrint("-------\(credentials.description)")
    }

    func testDeleteCredential() throws {
        try EAP8021XClient.deleteEAPCredential(ssid: "xxxxxxx")
        debugPrint("---")
    }

    #if os(macOS)

        func testFetchProfiles() throws {
            let profiles = EAP8021XClient.listAllProfiles()
            debugPrint("-----")
        }

        func testFetchProfile() throws {
            let profiles = EAP8021XClient.profileWithSSID("xxxxx")
            debugPrint("-----")
        }

        func testDeleteProfile() throws {
            let result = EAP8021XClient.removeProfileWithSSID("xxxx")
            debugPrint(result)
        }

        func testImportProfile() throws {
            let cerContent = """
                        xxxxxxx
            """.replacingOccurrences(of: "\n", with: "")

            if let cerData = Data(base64Encoded: cerContent) {
                let result = EAP8021XClient.createProfile(ssid: "xxxxx",
                                                          acceptEAPTypes: [.peap],
                                                          userDefinedName: "xxxxxx",
                                                          domainName: nil, securityType: .any,
                                                          outerIdentity: nil,
                                                          ttlSInnerAuthentication: .mschapv2,
                                                          trustedServerName: nil,
                                                          trustedCertificate: [cerData])
                debugPrint(result)
            }
        }
    #endif
}
