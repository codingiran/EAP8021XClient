// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EAP8021XClient",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "EAP8021XClient",
            targets: ["EAP8021XClient"]
        ),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "EAP8021XClient",
            dependencies: [
                .targetItem(name: "EAP8021XClientObjc", condition: .when(platforms: [.macOS])),
            ],
            resources: [.copy("../Resources/PrivacyInfo.xcprivacy")],
            swiftSettings: [
                .define("SPM_EAP8021X_ENABLED", .when(platforms: [.macOS])),
            ]
        ),
        .target(
            name: "EAP8021XClientObjc",
            path: "Sources/EAP8021XClientObjc",
            resources: [.copy("../Resources/PrivacyInfo.xcprivacy")],
            publicHeadersPath: "include/",
            cSettings: [
                .headerSearchPath("headers/", .when(platforms: [.macOS])),
                .headerSearchPath("headers/CoreFoundation/", .when(platforms: [.macOS])),
                .headerSearchPath("headers/EAP8021X/", .when(platforms: [.macOS])),
                .headerSearchPath("headers/SystemConfiguration/", .when(platforms: [.macOS])),
                .headerSearchPath("headers/Security/", .when(platforms: [.macOS])),
            ],
            linkerSettings: [
                .linkedFramework("Security", .when(platforms: [.iOS, .macOS])),
                .linkedFramework("Network", .when(platforms: [.iOS, .macOS])),
                .linkedFramework("SystemConfiguration", .when(platforms: [.iOS, .macOS])),
                .linkedFramework("NetworkExtension", .when(platforms: [.iOS])),
                .linkedFramework("CoreWLAN", .when(platforms: [.macOS])),
                .linkedFramework("EAP8021X", .when(platforms: [.macOS])),
                .unsafeFlags(["-F", "/System/Library/PrivateFrameworks"]),
            ]
        ),
        .testTarget(
            name: "EAP8021XClientTests",
            dependencies: [
                "EAP8021XClient",
            ]
        ),
    ]
)
