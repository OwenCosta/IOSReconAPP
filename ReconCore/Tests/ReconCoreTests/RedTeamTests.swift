import XCTest
@testable import ReconCore

final class RedTeamTests: XCTestCase {
    // Reverse shells
    func testReverseShells() {
        XCTAssertEqual(RedTeam.parseTarget("10.10.14.3:4444")?.0, "10.10.14.3")
        XCTAssertEqual(RedTeam.parseTarget("10.10.14.3 4444")?.1, 4444)
        XCTAssertNil(RedTeam.parseTarget("nope"))
        let shells = RedTeam.reverseShells(lhost: "1.2.3.4", lport: 9001)
        XCTAssertTrue(shells.contains { $0.cmd.contains("/dev/tcp/1.2.3.4/9001") })
        XCTAssertTrue(shells.contains { $0.name == "Python3" && $0.cmd.contains("1.2.3.4") && $0.cmd.contains("9001") })
        let out = RedTeam.runReverseShell("1.2.3.4:9001")
        XCTAssertTrue(out.sections.contains { $0.title.contains("Listeners") })
    }

    // PowerShell -EncodedCommand (UTF-16LE base64), known vector
    func testPowerShellEncode() {
        XCTAssertEqual(RedTeam.powershellEncode("whoami"), "dwBoAG8AYQBtAGkA")
    }

    // Default creds
    func testDefaultCreds() {
        XCTAssertTrue(RedTeam.lookupCreds("tomcat").contains { $0.user == "tomcat" })
        XCTAssertTrue(RedTeam.lookupCreds("idrac").contains { $0.pass == "calvin" })
        XCTAssertEqual(RedTeam.lookupCreds("zzzznotreal").count, 0)
        XCTAssertGreaterThan(RedTeam.lookupCreds("").count, 40)   // empty => all
    }

    // CVSS v3.1 known vectors
    func testCVSS() {
        XCTAssertEqual(CVSS.score(vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")?.score, 9.8)
        XCTAssertEqual(CVSS.score(vector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")?.score, 10.0)
        XCTAssertEqual(CVSS.score(vector: "AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")?.score, 1.8)
        XCTAssertEqual(CVSS.score(vector: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")?.severity, .medium)
        XCTAssertNil(CVSS.score(vector: "garbage"))
        // tolerate the CVSS:3.1/ prefix
        let out = CVSS.run("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        XCTAssertTrue(out.sections.first!.items.contains { $0.label == "Score" && $0.value == "9.8" })
    }

    // JWT forge round-trips through the cracker/verifier
    func testJWTForge() {
        let token = JWTCrack.forge(payload: "{\"user\":\"admin\",\"admin\":true}", secret: "secret")!
        let r = JWTCrack.crack(token: token, candidates: ["wrong", "secret"])
        XCTAssertEqual(r?.secret, "secret")
        // alg=none path
        let out = JWTCrack.runForge("{\"user\":\"guest\"}")
        XCTAssertTrue(out.sections.first!.items.contains { $0.value.hasSuffix(".") })
    }

    // Learn content integrity
    func testLearnContent() {
        XCTAssertGreaterThanOrEqual(LearnContent.sections.count, 8)
        XCTAssertGreaterThan(LearnContent.termCount, 50)
        for sec in LearnContent.sections {
            XCTAssertFalse(sec.title.isEmpty)
            XCTAssertFalse(sec.entries.isEmpty)
            for e in sec.entries { XCTAssertFalse(e.term.isEmpty); XCTAssertGreaterThan(e.definition.count, 20) }
        }
    }

    func testCatalogRedTeam() {
        XCTAssertTrue(ToolCategory.allCases.contains(.redteam))
        XCTAssertGreaterThanOrEqual(ToolCatalog.tools(in: .redteam).count, 3)
        for id in ["revshell", "ps-encode", "default-creds", "jwt-forge", "cvss"] {
            XCTAssertTrue(ToolCatalog.all.contains { $0.id == id }, "missing \(id)")
        }
    }
}
