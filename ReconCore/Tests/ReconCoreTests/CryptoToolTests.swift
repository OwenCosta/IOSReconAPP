import XCTest
@testable import ReconCore

final class CryptoToolTests: XCTestCase {
    func B(_ s: String) -> BigUInt { BigUInt(decimal: s)! }

    // MARK: RSA
    func testModInverse() {
        XCTAssertEqual(RSATool.modInverse(B("17"), B("3120"))?.description, "2753")
        XCTAssertNil(RSATool.modInverse(B("6"), B("9")))   // gcd ≠ 1
    }
    func testPrimality() {
        XCTAssertTrue(RSATool.isProbablePrime(B("61")))
        XCTAssertTrue(RSATool.isProbablePrime(B("2147483647")))      // Mersenne prime
        XCTAssertFalse(RSATool.isProbablePrime(B("3233")))           // 61*53
        XCTAssertTrue(RSATool.isProbablePrime(B("32416190071")))     // known prime
    }
    func testFactorSmallSemiprime() {
        XCTAssertEqual(RSATool.factor(B("3233")), [B("53"), B("61")])
        XCTAssertEqual(RSATool.factor(B("1005973")), [B("997"), B("1009")])
    }
    func testFactorClosePrimesFermat() {
        // Two primes close together → Fermat should split quickly.  10007 * 10009
        XCTAssertEqual(RSATool.factor(B("100160063")), [B("10007"), B("10009")])
    }
    func testFullTextbookRSA() {
        // n=3233 (61*53), e=17, d=2753. Encrypt 65 ('A'): 65^17 mod 3233 = 2790.
        let out = RSATool.run("n=3233\ne=17\nc=2790")
        let flat = out.sections.flatMap { $0.items.map { "\($0.label)=\($0.value)" } }.joined(separator: "|")
        XCTAssertTrue(flat.contains("d (private exponent)=2753"), flat)
        XCTAssertTrue(flat.contains("Decrypted m=65"), flat)
    }
    func testLowExponentCubeRoot() {
        // m=1234567, e=3, c=m^3 (less than n) → recover by integer cube root.
        let m = B("1234567")
        let c = m * m * m
        let out = RSATool.run("n=99999999999999999999999\ne=3\nc=\(c)")
        let flat = out.sections.flatMap { $0.items.map(\.value) }.joined(separator: "|")
        XCTAssertTrue(flat.contains("1234567"), flat)
    }

    // MARK: Substitution — accuracy probe (deterministic seed)
    func testSubstitutionAccuracy() {
        let plain = """
        the art of war teaches us to rely not on the likelihood of the enemy not coming but on our own readiness to
        receive him not on the chance of his not attacking but rather on the fact that we have made our position
        unassailable and so the clever combatant imposes his will on the enemy but does not allow the enemy to impose
        his will on him
        """
        // Build a fixed substitution key (Caesar+scramble) and encrypt.
        let key = "QWERTYUIOPASDFGHJKLZXCVBNM"   // plaintext A-Z maps to this
        func enc(_ t: String) -> String {
            let k = Array(key)
            return String(t.unicodeScalars.map { u -> Character in
                if u.value >= 97 && u.value <= 122 { return k[Int(u.value - 97)] }
                return Character(u)
            }).lowercased()
        }
        let cipher = enc(plain)
        let (recovered, _) = SubstitutionSolver.solve(cipher)
        // letter-level accuracy
        let p = Array(plain.lowercased().unicodeScalars).filter { $0.value >= 97 && $0.value <= 122 }
        let r = Array(recovered.lowercased().unicodeScalars).filter { $0.value >= 97 && $0.value <= 122 }
        XCTAssertEqual(p.count, r.count)
        let correct = zip(p, r).filter { $0.0 == $0.1 }.count
        let acc = Double(correct) / Double(p.count)
        XCTAssertGreaterThan(acc, 0.9, "substitution accuracy \(acc)")
    }
}
