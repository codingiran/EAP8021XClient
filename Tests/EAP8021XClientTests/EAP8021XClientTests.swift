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
        let ssid = "ZenNet-Radius-Test9"
        try EAP8021XClient.saveEAPCredential(ssid: ssid,
                                             username: "lazy.zhu@zenlayer.com",
                                             password: "1qaz@WSX",
                                             kind: "Zurbo 802.1x Password",
                                             service: "com.apple.network.eap.user.item.wlan.ssid.\(ssid)",
                                             comment: "For ZenLayer",
                                             allAppsAccess: false,
                                             useSystemKeychain: false)
    }

    func testFetchCredential() throws {
        let credential = try EAP8021XClient.getEAPCredential(ssid: nil, comment: "For ZenLayer")
        debugPrint("-------\(String(describing: credential?.description))")
    }

    func testFetchCredentials() throws {
        let credentials = try EAP8021XClient.getEAPCredentials(ssid: nil, comment: "For ZenLayer", returnData: true)
        debugPrint("-------\(credentials.description)")
    }

    func testDeleteCredential() throws {
        try EAP8021XClient.deleteEAPCredential(ssid: "ZenNet-Radius-Iran")
        debugPrint("---")
    }

    #if os(macOS)

        func testFetchProfiles() throws {
            let profiles = EAP8021XClient.listAllProfiles()
            debugPrint("-----")
        }

        func testFetchProfile() throws {
            let profiles = EAP8021XClient.profileWithSSID("ZenNet-Radius-Test")
            debugPrint("-----")
        }

        func testDeleteProfile() throws {
            let result = EAP8021XClient.removeProfileWithSSID("ZenNet-Radius-Test")
            debugPrint(result)
        }

        func testImportProfile() throws {
            let cerContent = """
            MIIEHjCCAwagAwIBAgIUexFK3dzhVtSqrNohoIjMq9iOkfYwDQYJKoZIhvcNAQEL
            BQAwejELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0ppYW5nc3UxEDAOBgNVBAcMB05h
            bnRvbmcxFjAUBgNVBAoMDVplbmxheWVyIEluYy4xFjAUBgNVBAsMDVplbmxheWVy
            IEluYy4xFzAVBgNVBAMMDlR1cmJvWCBSb290IENBMB4XDTI0MTIzMDA1Mjg1OVoX
            DTI3MDQwNDA1Mjg1OVowejELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0ppYW5nc3Ux
            EDAOBgNVBAcMB05hbnRvbmcxFjAUBgNVBAoMDVplbmxheWVyIEluYy4xFjAUBgNV
            BAsMDVplbmxheWVyIEluYy4xFzAVBgNVBAMMDlR1cmJvWCBSb290IENBMIIBIjAN
            BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1xOG1APNNrHfIiHcCyrC9Axkzau
            XokSkksal/qleW0tUDvRU0dEzAQmVx0U4+voYO6K3UbdX+uVrY8Om1qyKoi6x7gG
            sir7Coq6mPUJl2r/LgHrP2bbPVPdYeMZyjQNf+n2ArA3UDJKkEP702nVF1YMLEIi
            qIE2glyOfZOWRtB8iKciJzSFqYv4IkjP0X8W0hezK0ST05VXXRtU/YEKDKF1pq+x
            FL8ubCShPaQP4NUfdDi6dWZpJoaz7emZD/EhffbniVvrWk46CTzQs4AtKLpVbHYo
            twFixxLGECqt88l4/FwnLrAbdYRoax5vnugl+Zgjd3EWj9bbhyugRvIpIQIDAQAB
            o4GbMIGYMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMB0GA1Ud
            DgQWBBSHBK2buvdzHzoaMnBMb39wltlVEDAyBgNVHREEKzApggx6ZW5sYXllci5j
            b22BE3R1cmJveEB6ZW5sYXllci5jb22HBH8AAAEwHwYDVR0jBBgwFoAUhwStm7r3
            cx86GjJwTG9/cJbZVRAwDQYJKoZIhvcNAQELBQADggEBAGgEYvgDR2SKyHAL/MzC
            UrxujzEJNz+3vaPy+z9y+N6IcdmrgqstQ/4xxTedD+w/g+n7ON7FKQYBuKp1PDic
            rGe1bKwu6JBKiq9e0kvYfCY60XTsq+BHnel2wyzk+ODqv5rzzFtMLIObsYlKOszL
            UW2O+T/g5j3tsn5MLf981NbjKA8BTfF2oHJmZuotXMayrztgbAG5PGVIvKEOUzPU
            Ij1R9ttgZokVPFi11+gIlG8LILSCZ4eOjeNadhWsAZAB+CBsSuM2xwleiqcSnZyX
            xc0d2mt611IPI2C6K9FJCYPcTjiJQKri2ydzDApoxkLFVmbqfGunj/MD+b2F4o/K
            pNw=
            """.replacingOccurrences(of: "\n", with: "")

            if let cerData = Data(base64Encoded: cerContent) {
                let result = EAP8021XClient.createProfile(ssid: "ZenNet-Radius-Test", acceptEAPTypes: [.PEAP], userDefinedName: "TurboXWIFI", domainName: nil, securityType: .any, outerIdentity: nil, ttlSInnerAuthentication: .mschaPv2, trustedServerName: nil, trustedCertificate: [cerData])

                debugPrint(result)
            }
        }
    #endif
}
