// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ReconCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "ReconCore", targets: ["ReconCore"])
    ],
    targets: [
        .target(name: "ReconCore", resources: [.process("Resources")]),
        .testTarget(name: "ReconCoreTests", dependencies: ["ReconCore"])
    ]
)
