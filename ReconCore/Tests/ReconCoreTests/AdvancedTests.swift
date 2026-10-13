import XCTest
@testable import ReconCore

final class AdvancedTests: XCTestCase {

    // MARK: JWT cracking
    func testJWTCrack() {
        // Mint an HS256 token signed with "secret".
        let header = Data(#"{"alg":"HS256","typ":"JWT"}"#.utf8).base64EncodedString()
        let payload = Data(#"{"sub":"1337","role":"admin"}"#.utf8).base64EncodedString()
        func b64url(_ s: String) -> String { s.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
        let signingInput = "\(b64url(header)).\(b64url(payload))"
        let sig = JWTCrack.base64url(JWTCrack.mac(alg: "HS256", key: Array("secret".utf8), message: Array(signingInput.utf8))!)
        let token = "\(signingInput).\(sig)"

        let r = JWTCrack.crack(token: token, candidates: JWTCrack.weakSecrets)
        XCTAssertEqual(r?.alg, "HS256")
        XCTAssertEqual(r?.secret, "secret")

        // Wrong-only list → no match.
        XCTAssertNil(JWTCrack.crack(token: token, candidates: ["nope", "wrong"])?.secret)
        // Full tool reports a critical finding.
        XCTAssertTrue(JWTCrack.run(token).findings.contains { $0.severity == .critical && $0.title.contains("secret") })
    }

    // MARK: Vigenère
    func testVigenereDecryptKnownVector() {
        XCTAssertEqual(Vigenere.encrypt("ATTACKATDAWN", key: "LEMON"), "LXFOPVEFRNHR")
        XCTAssertEqual(Vigenere.decrypt("LXFOPVEFRNHR", key: "LEMON"), "ATTACKATDAWN")
    }

    func testVigenereCryptanalysis() {
        let plain = """
        the index of coincidence is a statistic that measures how likely it is that two randomly \
        chosen letters from a text are the same this value tends to be higher for natural language \
        than for random text and it lets an analyst estimate the length of a repeating key used in a \
        polyalphabetic cipher once the key length is known each column can be attacked as a simple caesar shift
        """
        let cipher = Vigenere.encrypt(plain, key: "LEMON")
        let a = Vigenere.analyze(cipher)
        XCTAssertNotNil(a)
        XCTAssertEqual(a?.key, "LEMON")
        XCTAssertEqual(a?.keyLength, 5)
        XCTAssertEqual(a?.plaintext, plain)
    }

    // MARK: Secrets
    func testSecretScanner() {
        // Tokens are assembled from fragments so no contiguous dummy "secret" sits in the source
        // (keeps CI secret-scanning push protection happy); the scanner still sees the full strings.
        let aws = "AKIA" + "IOSFODNN7EXAMPLE"
        let gh = "ghp_" + String(repeating: "a", count: 36)
        let goog = "AIza" + String(repeating: "B", count: 35)
        let stripe = "sk_" + "live_" + "0123456789abcdefghijklmn"
        let pk = "-----BEGIN " + "RSA PRIVATE KEY-----"
        let blob = """
        const AWS_KEY = "\(aws)";
        github_token: \(gh)
        GOOGLE = "\(goog)"
        \(pk)
        api_key = "\(stripe)"
        """
        let names = Set(SecretScanner.scan(blob).map(\.title))
        XCTAssertTrue(names.contains("AWS Access Key ID"))
        XCTAssertTrue(names.contains("GitHub Token"))
        XCTAssertTrue(names.contains("Private Key Block"))
        XCTAssertTrue(names.contains("Stripe Live Secret Key"))
        XCTAssertTrue(SecretScanner.scan("just some normal text with no secrets here at all").allSatisfy { $0.severity == .low } )
    }

    func testEntropy() {
        XCTAssertGreaterThan(SecretScanner.entropy("aB3xK9mPqR7wTzL2"), 3.0)
        XCTAssertLessThan(SecretScanner.entropy("aaaaaaaa"), 0.1)
    }

    // MARK: New encoders
    func testBase58() {
        XCTAssertEqual(CTFEncoders.base58Decode("StV1DL6CwTryKyV").flatMap { String(data: $0, encoding: .utf8) }, "hello world")
        XCTAssertNil(CTFEncoders.base58Decode("0OIl"))   // chars not in alphabet
    }

    func testAscii85() {
        XCTAssertEqual(CTFEncoders.ascii85Decode("FCfN8").flatMap { String(data: $0, encoding: .utf8) }, "test")
        XCTAssertEqual(CTFEncoders.ascii85Decode("<~FCfN8~>").flatMap { String(data: $0, encoding: .utf8) }, "test")
    }

    func testMorse() {
        XCTAssertEqual(CTFEncoders.morseDecode(".... . .-.. .-.. ---"), "HELLO")
        XCTAssertEqual(CTFEncoders.morseDecode("-- --- .-. ... . / -.-. --- -.. ."), "MORSE CODE")
        XCTAssertNil(CTFEncoders.morseDecode("not morse at all"))
    }

    func testMagicUsesNewCodecs() {
        // The new codecs are registered as Magic transforms and decode correctly.
        func t(_ name: String) -> ((String) -> String?)? { MagicDecoder.transforms.first { $0.name == name }?.apply }
        XCTAssertEqual(t("Morse")?(".... . .-.. .-.. ---"), "HELLO")
        XCTAssertEqual(t("Base58")?("StV1DL6CwTryKyV"), "hello world")
        XCTAssertEqual(t("Ascii85")?("FCfN8"), "test")
        // End-to-end: a flag hidden under two Base64 layers is auto-recovered.
        let inner = Data("flag{magic_layers}".utf8).base64EncodedString()
        let outer = Data(inner.utf8).base64EncodedString()
        XCTAssertTrue(MagicDecoder.solve(outer).contains { $0.flags.contains("flag{magic_layers}") })
    }

    // MARK: Portable hashing wired into Digests
    func testDigestsWorkWithoutCryptoKitPath() {
        XCTAssertEqual(Digests.hex(.sha256, "abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(Digests.hex(.md5, "abc"), "900150983cd24fb0d6963f7d28e17f72")
        XCTAssertEqual(Digests.hex(.sha1, "abc"), "a9993e364706816aba3e25717850c26c9cd0d89d")
    }

    func testCatalogGrew() {
        XCTAssertGreaterThanOrEqual(ToolCatalog.tools(in: .ctf).count, 7)
        XCTAssertTrue(ToolCatalog.all.contains { $0.id == "jwt-crack" })
        XCTAssertTrue(ToolCatalog.all.contains { $0.id == "vigenere" })
        XCTAssertTrue(ToolCatalog.all.contains { $0.id == "secrets-text" })
    }
}
