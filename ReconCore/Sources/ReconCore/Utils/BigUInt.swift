import Foundation

/// A compact arbitrary-precision unsigned integer (base 2^32 limbs, little-endian), enough for the
/// RSA toolkit: parse/format, +, −, ×, divmod, modpow, gcd, isqrt. Not constant-time — for CTF/analysis use.
public struct BigUInt: Comparable, Equatable, CustomStringConvertible, Sendable {
    public private(set) var limbs: [UInt32]   // little-endian, no trailing zero limbs (zero == [])

    init(limbs: [UInt32]) { self.limbs = limbs; normalize() }
    public init() { limbs = [] }
    public init(_ v: UInt64) {
        var l: [UInt32] = []
        var x = v
        while x > 0 { l.append(UInt32(x & 0xFFFFFFFF)); x >>= 32 }
        limbs = l
    }

    private mutating func normalize() { while limbs.last == 0 { limbs.removeLast() } }
    public var isZero: Bool { limbs.isEmpty }
    public var isEven: Bool { limbs.first.map { $0 & 1 == 0 } ?? true }

    // MARK: Parsing

    public init?(decimal: String) {
        let s = decimal.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, s.allSatisfy({ $0.isNumber }) else { return nil }
        var acc = BigUInt()
        for ch in s { acc = acc.mulSmall(10) + BigUInt(UInt64(ch.wholeNumberValue!)) }
        self = acc
    }

    public init?(hex: String) {
        var s = hex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.hasPrefix("0x") { s.removeFirst(2) }
        s = s.replacingOccurrences(of: "_", with: "").replacingOccurrences(of: " ", with: "")
        guard !s.isEmpty, s.allSatisfy({ $0.isHexDigit }) else { return nil }
        var l: [UInt32] = []
        var chars = Array(s)
        while !chars.isEmpty {
            let take = min(8, chars.count)
            let chunk = String(chars.suffix(take))
            chars.removeLast(take)
            l.append(UInt32(chunk, radix: 16)!)
        }
        self = BigUInt(limbs: l)
    }

    // MARK: Comparison

    public static func < (a: BigUInt, b: BigUInt) -> Bool {
        if a.limbs.count != b.limbs.count { return a.limbs.count < b.limbs.count }
        for i in stride(from: a.limbs.count - 1, through: 0, by: -1) where a.limbs[i] != b.limbs[i] {
            return a.limbs[i] < b.limbs[i]
        }
        return false
    }
    public static func == (a: BigUInt, b: BigUInt) -> Bool { a.limbs == b.limbs }

    // MARK: Add / sub / mul

    public static func + (a: BigUInt, b: BigUInt) -> BigUInt {
        var out: [UInt32] = []
        var carry: UInt64 = 0
        let n = Swift.max(a.limbs.count, b.limbs.count)
        out.reserveCapacity(n + 1)
        for i in 0..<n {
            let s = carry + UInt64(i < a.limbs.count ? a.limbs[i] : 0) + UInt64(i < b.limbs.count ? b.limbs[i] : 0)
            out.append(UInt32(s & 0xFFFFFFFF)); carry = s >> 32
        }
        if carry > 0 { out.append(UInt32(carry)) }
        return BigUInt(limbs: out)
    }

    /// Precondition: a >= b.
    public static func - (a: BigUInt, b: BigUInt) -> BigUInt {
        precondition(a >= b, "BigUInt subtraction underflow")
        var out: [UInt32] = []
        var borrow: Int64 = 0
        for i in 0..<a.limbs.count {
            let d = Int64(a.limbs[i]) - Int64(i < b.limbs.count ? b.limbs[i] : 0) - borrow
            if d < 0 { out.append(UInt32(d + 0x1_0000_0000)); borrow = 1 }
            else { out.append(UInt32(d)); borrow = 0 }
        }
        return BigUInt(limbs: out)
    }

    public func mulSmall(_ m: UInt32) -> BigUInt {
        if m == 0 || isZero { return BigUInt() }
        var out: [UInt32] = []
        var carry: UInt64 = 0
        for limb in limbs {
            let p = UInt64(limb) * UInt64(m) + carry
            out.append(UInt32(p & 0xFFFFFFFF)); carry = p >> 32
        }
        if carry > 0 { out.append(UInt32(carry)) }
        return BigUInt(limbs: out)
    }

    public static func * (a: BigUInt, b: BigUInt) -> BigUInt {
        if a.isZero || b.isZero { return BigUInt() }
        var out = [UInt32](repeating: 0, count: a.limbs.count + b.limbs.count)
        for i in 0..<a.limbs.count {
            var carry: UInt64 = 0
            let ai = UInt64(a.limbs[i])
            for j in 0..<b.limbs.count {
                let sum = UInt64(out[i + j]) + ai * UInt64(b.limbs[j]) + carry
                out[i + j] = UInt32(sum & 0xFFFFFFFF); carry = sum >> 32
            }
            out[i + b.limbs.count] += UInt32(carry)
        }
        return BigUInt(limbs: out)
    }

    // MARK: Division

    /// Fast path for a single-limb divisor; returns (quotient, remainder).
    public func divModSmall(_ d: UInt32) -> (BigUInt, UInt32) {
        var q = [UInt32](repeating: 0, count: limbs.count)
        var rem: UInt64 = 0
        for i in stride(from: limbs.count - 1, through: 0, by: -1) {
            let cur = (rem << 32) | UInt64(limbs[i])
            q[i] = UInt32(cur / UInt64(d)); rem = cur % UInt64(d)
        }
        return (BigUInt(limbs: q), UInt32(rem))
    }

    /// General long division (quotient digit found by binary search per limb). Returns (q, r).
    public static func divMod(_ a: BigUInt, _ b: BigUInt) -> (BigUInt, BigUInt) {
        precondition(!b.isZero, "division by zero")
        if a < b { return (BigUInt(), a) }
        if b.limbs.count == 1 { let (q, r) = a.divModSmall(b.limbs[0]); return (q, BigUInt(UInt64(r))) }
        var rem = BigUInt()
        var quot = [UInt32](repeating: 0, count: a.limbs.count)
        for i in stride(from: a.limbs.count - 1, through: 0, by: -1) {
            rem.limbs.insert(a.limbs[i], at: 0); rem.normalize()   // rem = rem * 2^32 + limb
            if rem < b { continue }
            var lo: UInt64 = 0, hi: UInt64 = 0xFFFFFFFF, best: UInt64 = 0
            while lo <= hi {
                let mid = lo + (hi - lo) / 2
                if b.mulSmall(UInt32(mid)) <= rem { best = mid; lo = mid + 1 }
                else { if mid == 0 { break }; hi = mid - 1 }
            }
            quot[i] = UInt32(best)
            rem = rem - b.mulSmall(UInt32(best))
        }
        return (BigUInt(limbs: quot), rem)
    }

    public static func / (a: BigUInt, b: BigUInt) -> BigUInt { divMod(a, b).0 }
    public static func % (a: BigUInt, b: BigUInt) -> BigUInt { divMod(a, b).1 }

    // MARK: Number theory

    public func modpow(_ exponent: BigUInt, _ modulus: BigUInt) -> BigUInt {
        precondition(!modulus.isZero)
        if modulus == BigUInt(1) { return BigUInt() }
        var result = BigUInt(1)
        var base = self % modulus
        var exp = exponent
        let two = BigUInt(2)
        while !exp.isZero {
            if !exp.isEven { result = (result * base) % modulus }
            exp = exp / two
            base = (base * base) % modulus
        }
        return result
    }

    public static func gcd(_ x: BigUInt, _ y: BigUInt) -> BigUInt {
        var a = x, b = y
        while !b.isZero { let r = a % b; a = b; b = r }
        return a
    }

    /// Integer square root (floor).
    public func isqrt() -> BigUInt {
        if isZero { return BigUInt() }
        if self < BigUInt(4) { return BigUInt(1) }
        // initial guess: 2^(ceil(bits/2))
        let bits = (limbs.count - 1) * 32 + (32 - Int(limbs.last!.leadingZeroBitCount))
        var x = BigUInt(1)
        for _ in 0..<((bits + 2) / 2) { x = x.mulSmall(2) }
        let two = BigUInt(2)
        while true {
            // y = (x + self/x) / 2
            let y = (x + (self / x)) / two
            if y >= x { break }
            x = y
        }
        return x
    }

    // MARK: Output

    public func hexString() -> String {
        if isZero { return "0" }
        var s = String(limbs.last!, radix: 16)
        for i in stride(from: limbs.count - 2, through: 0, by: -1) {
            s += String(format: "%08x", limbs[i])
        }
        return s
    }

    public var description: String {
        if isZero { return "0" }
        var chunks: [String] = []
        var cur = self
        let billion: UInt32 = 1_000_000_000
        while !cur.isZero {
            let (q, r) = cur.divModSmall(billion)
            chunks.append(String(r)); cur = q
        }
        var out = chunks.removeLast()
        for c in chunks.reversed() { out += String(repeating: "0", count: 9 - c.count) + c }
        return out
    }

    /// Big-endian byte representation (for converting RSA integers to text).
    public func bytes() -> [UInt8] {
        if isZero { return [0] }
        var out: [UInt8] = []
        for limb in limbs {
            out.append(UInt8(limb & 0xFF)); out.append(UInt8((limb >> 8) & 0xFF))
            out.append(UInt8((limb >> 16) & 0xFF)); out.append(UInt8((limb >> 24) & 0xFF))
        }
        while out.last == 0 && out.count > 1 { out.removeLast() }
        return out.reversed()
    }
}
