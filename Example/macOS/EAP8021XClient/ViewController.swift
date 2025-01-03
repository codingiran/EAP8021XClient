//
//  ViewController.swift
//  EAP8021XClient
//
//  Created by CodingIran on 01/03/2025.
//  Copyright (c) 2025 CodingIran. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {
    override func viewDidLoad() {
        super.viewDidLoad()

        let profiles = Eap8021x.listProfiles()
        debugPrint("---")
        
//        Eap8021x.removeProfile(withSSID: "ZenNet-Radius-Test")
//        
//        return

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
            Eap8021x.createProfile(withSSID: "ZenNet-Radius-Test",
                                   acceptEAPTypes: [NSNumber(value: Eap8021xEAPType.PEAP.rawValue)],
                                   userDefinedName: "TurboXWIFI",
                                   domainName: nil,
                                   securityType: Eap8021xSecurityType.any,
                                   outerIdentity: nil,
                                   ttlSInnerAuthentication: Eap8021TTLSInnerAuthType.mschaPv2,
                                   trustedServerName: nil,
                                   trustedCertificate: [cerData])
        }
    }

    override var representedObject: Any? {
        didSet {
            // Update the view, if already loaded.
        }
    }
}
