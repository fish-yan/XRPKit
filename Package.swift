// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "XRPKit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v4),
    ],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "XRPKit",
            targets: ["XRPKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.5.1"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.4.0"),
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", .upToNextMinor(from: "0.10.0")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "XRPKit",
            dependencies: [
                .product(name: "secp256k1", package: "swift-secp256k1"),
                "CryptoSwift",
                "BigInt"
            ]),
        .testTarget(
            name: "XRPKitTests",
            dependencies: ["XRPKit"]),
    ]
)
