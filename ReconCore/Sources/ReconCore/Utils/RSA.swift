import Foundation

/// RSA helper for CTF / analysis: build a modulus from primes, factor small/weak moduli,
/// recover the private exponent, decrypt, and spot classic weaknesses (shared factors, close
/// primes, tiny exponent). All maths via the in-house BigUInt.
public enum RSATool {
    static let one = BigUInt(1), two = BigUInt(2)

    // MARK: Modular inverse (extended Euclid in the ring mod m)
    public static func modInverse(_ a: BigUInt, _ m: BigUInt) -> BigUInt? {
        guard !m.isZero, m != one else { return nil }
        var r = m, newr = a % m
        var t = BigUInt(), newt = one
        while !newr.isZero {
            let q = r / newr
            let tmpR = r - q * newr; r = newr; newr = tmpR
            let qt = (q * newt) % m
            let tmpT = (t + m - qt) % m; t = newt; newt = tmpT
        }
        return r == one ? t : nil
    }

    // MARK: Primality (Miller–Rabin, deterministic bases for < 3.3·10^24, probabilistic beyond)
    public static func isProbablePrime(_ n: BigUInt) -> Bool {
        if n < two { return false }
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] as [UInt64] {
            let bp = BigUInt(p)
            if n == bp { return true }
            if (n % bp).isZero { return false }
        }
        var d = n - one
        var s = 0
        while d.isEven { d = d / two; s += 1 }
        let nm1 = n - one
        for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] as [UInt64] {
            var x = BigUInt(a).modpow(d, n)
            if x == one || x == nm1 { continue }
            var composite = true
            for _ in 0..<(s - 1) { x = (x * x) % n; if x == nm1 { composite = false; break } }
            if composite { return false }
        }
        return true
    }

    // MARK: Integer k-th root (floor), and perfect-power test
    public static func iroot(_ n: BigUInt, _ k: Int) -> BigUInt {
        if n.isZero { return BigUInt() }
        if k == 2 { return n.isqrt() }
        func powk(_ x: BigUInt) -> BigUInt { var r = one; for _ in 0..<k { r = r * x }; return r }
        var lo = one, hi = two
        while powk(hi) <= n { hi = hi.mulSmall(2) }
        while lo < hi {
            let mid = (lo + hi + one) / two
            if powk(mid) <= n { lo = mid } else { hi = mid - one }
        }
        return lo
    }

    // MARK: Factoring (bounded so the UI never hangs)
    static let smallPrimes: [UInt32] = {
        var sieve = [Bool](repeating: true, count: 100_000)
        var ps: [UInt32] = []
        for i in 2..<100_000 where sieve[i] {
            ps.append(UInt32(i))
            var j = i * i; while j < 100_000 { sieve[j] = false; j += i }
        }
        return ps
    }()

    public static func factor(_ n: BigUInt) -> [BigUInt] {
        if n <= one { return [] }
        var remaining = n
        var factors: [BigUInt] = []
        // 1) trial division by small primes
        for p in smallPrimes {
            if remaining == one { break }
            let bp = BigUInt(UInt64(p))
            if bp * bp > remaining { break }
            while (remaining % bp).isZero { factors.append(bp); remaining = remaining / bp }
        }
        if remaining == one { return factors.sorted() }
        if isProbablePrime(remaining) { factors.append(remaining); return factors.sorted() }
        // 2) Fermat (close primes — very common in CTF)
        if let (p, q) = fermat(remaining, maxIterations: 200_000) {
            factors.append(contentsOf: [p, q]); return factors.sorted()
        }
        // 3) Pollard rho (Brent)
        if let f = pollardRho(remaining) {
            let g = remaining / f
            factors.append(contentsOf: [f, g]); return factors.sorted()
        }
        factors.append(remaining)   // give up: leave the composite as-is
        return factors.sorted()
    }

    static func fermat(_ n: BigUInt, maxIterations: Int) -> (BigUInt, BigUInt)? {
        if n.isEven { return (two, n / two) }
        var a = n.isqrt()
        if a * a < n { a = a + one }
        var iter = 0
        while iter < maxIterations {
            let b2 = a * a - n
            let b = b2.isqrt()
            if b * b == b2 { let p = a - b, q = a + b; if p > one && p < n { return (p, q) } ; if p <= one { return nil } }
            a = a + one; iter += 1
        }
        return nil
    }

    static func pollardRho(_ n: BigUInt) -> BigUInt? {
        if n.isEven { return two }
        var c = one
        while c < BigUInt(20) {
            var x = two, y = two, d = one
            func f(_ v: BigUInt) -> BigUInt { (v * v + c) % n }
            var guard_ = 0
            while d == one && guard_ < 2_000_000 {
                x = f(x); y = f(f(y))
                let diff = x >= y ? x - y : y - x
                d = BigUInt.gcd(diff, n)
                guard_ += 1
            }
            if d != one && d != n { return d }
            c = c + one
        }
        return nil
    }

    // MARK: Parse + run

    static func parse(_ input: String) -> [String: BigUInt] {
        var vals: [String: BigUInt] = [:]
        for rawLine in input.split(whereSeparator: { $0 == "\n" || $0 == ";" }) {
            let line = rawLine.replacingOccurrences(of: " ", with: "")
            guard let eq = line.firstIndex(where: { $0 == "=" || $0 == ":" }) else { continue }
            let key = String(line[..<eq]).lowercased()
            let valStr = String(line[line.index(after: eq)...])
            guard let v = valStr.hasPrefix("0x") ? BigUInt(hex: valStr) : (BigUInt(decimal: valStr) ?? BigUInt(hex: valStr)) else { continue }
            if ["n", "e", "p", "q", "d", "c", "phi", "m"].contains(key) { vals[key] = v }
        }
        return vals
    }

    public static func run(_ input: String) -> ToolOutput {
        var v = parse(input)
        var out = ToolOutput()
        var s = ReportSection("RSA", note: "Give any of n, e, p, q, d, c (ciphertext) as `key=value`, one per line (decimal or 0x…).")

        guard !v.isEmpty else {
            s.add("Usage", "e.g.  n=3233  e=17  c=2790   — or  p=61  q=53  e=17  c=2790", .low)
            out.sections = [s]; return out
        }

        if v["n"] == nil, let p = v["p"], let q = v["q"] { v["n"] = p * q }
        if let n = v["n"] { s.add("n", "\(n)  (\(n.hexString().count * 4)-ish bits)") }
        if let e = v["e"] { s.add("e", "\(e)") }

        // Factor n if we don't already have the primes.
        if v["p"] == nil, let n = v["n"], n > one {
            s.add("Factoring", "trying trial division · Fermat · Pollard rho…")
            let f = factor(n)
            if f.count == 2, f[0] * f[1] == n {
                v["p"] = f[0]; v["q"] = f[1]
                s.add("p", "\(f[0])", .high); s.add("q", "\(f[1])", .high)
                out.findings.append(Finding(.high, "RSA modulus factored", "n = p × q recovered on-device.", source: "rsa"))
            } else if f.count > 2 {
                s.add("Factors", f.map { "\($0)" }.joined(separator: " × "), .high)
            } else {
                s.add("Factoring", "could not factor on-device — paste p and q (e.g. from factordb.com)", .low)
            }
        }

        // Wiener's attack: recover a small d directly when factoring failed.
        if v["p"] == nil, v["d"] == nil, let e = v["e"], let n = v["n"], e > one {
            if let d = wiener(e: e, n: n) {
                v["d"] = d
                s.add("Wiener's attack", "small private exponent recovered", .critical)
                s.add("d (private exponent)", "\(d)", .critical)
                out.findings.append(Finding(.critical, "RSA private key recovered (Wiener's attack)", "d is small relative to n.", source: "rsa"))
            }
        }

        // φ(n) and private exponent.
        if let p = v["p"], let q = v["q"] {
            let phi = (p - one) * (q - one)
            s.add("φ(n)", "\(phi)")
            if let e = v["e"] {
                if let d = modInverse(e, phi) {
                    v["d"] = d
                    s.add("d (private exponent)", "\(d)", .critical)
                    out.findings.append(Finding(.critical, "RSA private key recovered", "d computed from the factored modulus.", source: "rsa"))
                } else {
                    s.add("d", "e is not invertible mod φ(n) (gcd(e,φ) ≠ 1)", .medium)
                }
            }
        }

        // Decrypt / weaknesses.
        if let c = v["c"], let n = v["n"] {
            if let d = v["d"] {
                let m = c.modpow(d, n)
                s.add("Decrypted m", "\(m)")
                s.add("  hex", m.hexString())
                if let text = asciiIfPrintable(m) { s.add("  text", text, .high)
                    for f in FlagHunter.find(in: text) { out.findings.append(Finding(.high, "Possible flag: \(f)", "RSA decryption", source: "ctf")) }
                }
            } else if let e = v["e"], e < BigUInt(10) {
                // Tiny-exponent: if m^e < n the ciphertext is just m^e with no modular wrap.
                let r = iroot(c, Int(e.description) ?? 3)
                if powEq(r, Int(e.description) ?? 3, c) {
                    s.add("Low-exponent attack", "c is a perfect e-th power — message not padded", .high)
                    s.add("Recovered m", "\(r)")
                    if let text = asciiIfPrintable(r) { s.add("  text", text, .high) }
                }
            }
        }

        // Shared-factor hint when two moduli are given (n and p where p is another modulus).
        out.sections = [s]
        return out
    }

    // MARK: Wiener's attack (small private exponent d)
    /// Recovers d when it is small, via the continued-fraction expansion of e/n. Returns d or nil.
    public static func wiener(e: BigUInt, n: BigUInt) -> BigUInt? {
        // Continued fraction of e/n, building convergents k_i/d_i on the fly.
        var x = e, y = n
        var hPrev2 = BigUInt(), hPrev1 = one   // numerators  (candidate k)
        var kPrev2 = one, kPrev1 = BigUInt()   // denominators (candidate d)
        var steps = 0
        while !y.isZero && steps < 400 {
            steps += 1
            let a = x / y
            let rem = x - a * y
            x = y; y = rem
            let h = a * hPrev1 + hPrev2     // k (numerator of convergent)
            let kk = a * kPrev1 + kPrev2    // d (denominator of convergent)
            hPrev2 = hPrev1; hPrev1 = h
            kPrev2 = kPrev1; kPrev1 = kk
            let kGuess = h, dGuess = kk
            if kGuess.isZero { continue }
            // φ = (e·d − 1) / k  must be a positive integer
            let edm1 = e * dGuess
            if edm1 < one { continue }
            let num = edm1 - one
            if !(num % kGuess).isZero { continue }
            let phi = num / kGuess
            if phi >= n { continue }
            // s = p + q = n − φ + 1 ; need s² − 4n to be a perfect square
            let s = n - phi + one
            let fourN = n.mulSmall(4)
            if s * s < fourN { continue }
            let disc = s * s - fourN
            let r = disc.isqrt()
            if r * r == disc { return dGuess }   // (p,q) are integers ⇒ d is correct
        }
        return nil
    }

    static func powEq(_ base: BigUInt, _ k: Int, _ target: BigUInt) -> Bool {
        var r = one; for _ in 0..<k { r = r * base }; return r == target
    }

    static func asciiIfPrintable(_ m: BigUInt) -> String? {
        let bytes = m.bytes()
        guard let str = String(bytes: bytes, encoding: .utf8) ?? String(bytes: bytes, encoding: .isoLatin1), !str.isEmpty else { return nil }
        let printable = str.unicodeScalars.filter { $0.value >= 32 && $0.value < 127 || $0 == "\n" }.count
        return Double(printable) / Double(str.unicodeScalars.count) > 0.8 ? str : nil
    }

    // MARK: Multi-key attacks

    /// Minimal signed big integer for the extended Euclidean algorithm.
    struct SBig {
        var mag: BigUInt; var neg: Bool
        init(_ m: BigUInt, _ n: Bool = false) { mag = m; neg = n && !m.isZero }
        static let zero = SBig(BigUInt())
        static func + (a: SBig, b: SBig) -> SBig {
            if a.neg == b.neg { return SBig(a.mag + b.mag, a.neg) }
            return a.mag >= b.mag ? SBig(a.mag - b.mag, a.neg) : SBig(b.mag - a.mag, b.neg)
        }
        static prefix func - (a: SBig) -> SBig { SBig(a.mag, !a.neg) }
        static func - (a: SBig, b: SBig) -> SBig { a + (-b) }
        static func * (a: SBig, b: SBig) -> SBig { SBig(a.mag * b.mag, a.neg != b.neg) }
    }

    /// Extended Euclid: returns (g, x, y) with x·a + y·b = g.
    static func egcd(_ a: BigUInt, _ b: BigUInt) -> (BigUInt, SBig, SBig) {
        var oldR = a, r = b
        var oldS = SBig(one), s = SBig.zero
        var oldT = SBig.zero, t = SBig(one)
        while !r.isZero {
            let q = oldR / r
            let qS = SBig(q)
            (oldR, r) = (r, oldR - q * r)
            (oldS, s) = (s, oldS - qS * s)
            (oldT, t) = (t, oldT - qS * t)
        }
        return (oldR, oldS, oldT)
    }

    /// Chinese Remainder Theorem over pairwise-coprime moduli → (residue, product).
    public static func crt(_ pairs: [(BigUInt, BigUInt)]) -> (BigUInt, BigUInt)? {
        guard var r = pairs.first?.0, var m = pairs.first?.1 else { return nil }
        for i in 1..<pairs.count {
            let (r2, m2) = pairs[i]
            guard let inv = modInverse(m % m2, m2) else { return nil }
            let diff = (r2 + m2 - (r % m2)) % m2
            let t = (diff * inv) % m2
            r = (r + m * t)
            m = m * m2
            r = r % m
        }
        return (r, m)
    }

    /// Same modulus, two coprime exponents: recover m without factoring.
    public static func commonModulus(n: BigUInt, e1: BigUInt, c1: BigUInt, e2: BigUInt, c2: BigUInt) -> BigUInt? {
        let (g, a, b) = egcd(e1, e2)
        guard g == one else { return nil }
        var base1 = c1 % n, base2 = c2 % n
        var ea = a, eb = b
        if ea.neg { guard let inv = modInverse(base1, n) else { return nil }; base1 = inv; ea = SBig(ea.mag) }
        if eb.neg { guard let inv = modInverse(base2, n) else { return nil }; base2 = inv; eb = SBig(eb.mag) }
        return (base1.modpow(ea.mag, n) * base2.modpow(eb.mag, n)) % n
    }

    /// Håstad broadcast: same small e, same m, e different moduli → CRT then e-th root.
    public static func hastad(_ pairs: [(c: BigUInt, n: BigUInt)], e: Int) -> BigUInt? {
        guard pairs.count >= e else { return nil }
        guard let (combined, _) = crt(pairs.map { ($0.c, $0.n) }) else { return nil }
        let m = iroot(combined, e)
        return powEq(m, e, combined) ? m : nil
    }

    static func parseMulti(_ input: String) -> [(n: BigUInt, e: BigUInt?, c: BigUInt?)] {
        var keys: [(n: BigUInt, e: BigUInt?, c: BigUInt?)] = []
        for line in input.split(whereSeparator: { $0 == "\n" }) {
            var d: [String: BigUInt] = [:]
            for tok in line.split(whereSeparator: { $0 == " " || $0 == "," || $0 == "\t" }) {
                guard let eq = tok.firstIndex(where: { $0 == "=" || $0 == ":" }) else { continue }
                let k = String(tok[..<eq]).lowercased()
                let vs = String(tok[tok.index(after: eq)...])
                if let v = vs.hasPrefix("0x") ? BigUInt(hex: vs) : (BigUInt(decimal: vs) ?? BigUInt(hex: vs)) { d[k] = v }
            }
            if let n = d["n"] { keys.append((n, d["e"], d["c"])) }
        }
        return keys
    }

    public static func runMulti(_ input: String) -> ToolOutput {
        let keys = parseMulti(input)
        var out = ToolOutput()
        var s = ReportSection("RSA multi-key attacks",
                              note: "One key per line: `n=… e=… c=…`. Detects common-modulus and Håstad broadcast automatically.")
        guard keys.count >= 2 else {
            s.add("Usage", "Common modulus: same n, two e/c.  Håstad: same small e, different n, same m.", .low)
            out.sections = [s]; return out
        }
        func reveal(_ m: BigUInt, _ how: String) {
            s.add(how, "recovered m", .critical)
            s.add("m", "\(m)")
            if let t = asciiIfPrintable(m) { s.add("text", t, .high)
                for f in FlagHunter.find(in: t) { out.findings.append(Finding(.high, "Possible flag: \(f)", how, source: "ctf")) } }
            out.findings.append(Finding(.critical, "RSA broken: \(how)", source: "rsa"))
        }

        // Common modulus: identical n across (at least) two keys with different exponents.
        if let n = keys.first?.n, keys.allSatisfy({ $0.n == n }),
           keys.count >= 2, let e1 = keys[0].e, let c1 = keys[0].c, let e2 = keys[1].e, let c2 = keys[1].c, e1 != e2 {
            if let m = commonModulus(n: n, e1: e1, c1: c1, e2: e2, c2: c2) { reveal(m, "Common-modulus attack") ; out.sections = [s]; return out }
        }
        // Håstad broadcast: same small e, distinct moduli.
        if let e = keys.first?.e, let ei = Int(e.description), ei <= 10, keys.allSatisfy({ $0.e == e }),
           keys.allSatisfy({ $0.c != nil }) {
            let pairs = keys.map { (c: $0.c!, n: $0.n) }
            if let m = hastad(pairs, e: ei) { reveal(m, "Håstad broadcast attack (e=\(ei))"); out.sections = [s]; return out }
        }
        s.add("Result", "no multi-key attack applied — need same n with two exponents, or same small e across ≥e moduli", .low)
        out.sections = [s]
        return out
    }
}
