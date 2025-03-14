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

        let profiles = EAPOLClientWrapper.listProfiles()
        debugPrint("---")

//        EAPOLClientWrapper.removeProfile(withSSID: "xxxxxx")
//
//        return

        let cerContent = """
        xxxx
        """.replacingOccurrences(of: "\n", with: "")

        if let cerData = Data(base64Encoded: cerContent) {
            EAPOLClientWrapper.createProfile(withSSID: "xxxx",
                                             acceptEAPTypes: [NSNumber(value: EAP8021xEAPType.PEAP.rawValue)],
                                             userDefinedName: "xxxx",
                                             domainName: nil,
                                             securityType: EAP8021xSecurityType.any,
                                             outerIdentity: nil,
                                             ttlSInnerAuthentication: EAP8021TTLSInnerAuthType.mschaPv2,
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
