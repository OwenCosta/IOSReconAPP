import Foundation

// Portable, dependency-free implementations of the common digests, so hashing, HMAC and the
// JWT cracker work identically on iOS and on the Linux CI/test host (no CryptoKit required).

public enum PureHash {

    // MARK: SHA-256

    private static let k256: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    public static func sha256(_ message: [UInt8]) -> [UInt8] {
        var h: [UInt32] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        var msg = message
        let bitLen = UInt64(message.count) &* 8
        msg.append(0x80)
        while msg.count % 64 != 56 { msg.append(0) }
        for i in stride(from: 56, through: 0, by: -8) { msg.append(UInt8((bitLen >> UInt64(i)) & 0xff)) }

        func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }
        var w = [UInt32](repeating: 0, count: 64)
        var chunk = 0
        while chunk < msg.count {
            for i in 0..<16 {
                let j = chunk + i * 4
                w[i] = (UInt32(msg[j]) << 24) | (UInt32(msg[j+1]) << 16) | (UInt32(msg[j+2]) << 8) | UInt32(msg[j+3])
            }
            for i in 16..<64 {
                let s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
                let s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
                w[i] = w[i-16] &+ s0 &+ w[i-7] &+ s1
            }
            var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7]
            for i in 0..<64 {
                let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
                let ch = (e & f) ^ (~e & g)
                let t1 = hh &+ s1 &+ ch &+ k256[i] &+ w[i]
                let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let t2 = s0 &+ maj
                hh = g; g = f; f = e; e = d &+ t1; d = c; c = b; b = a; a = t1 &+ t2
            }
            h[0] = h[0] &+ a; h[1] = h[1] &+ b; h[2] = h[2] &+ c; h[3] = h[3] &+ d
            h[4] = h[4] &+ e; h[5] = h[5] &+ f; h[6] = h[6] &+ g; h[7] = h[7] &+ hh
            chunk += 64
        }
        return bigEndianBytes(h)
    }

    // MARK: SHA-1

    public static func sha1(_ message: [UInt8]) -> [UInt8] {
        var h0: UInt32 = 0x67452301, h1: UInt32 = 0xEFCDAB89, h2: UInt32 = 0x98BADCFE, h3: UInt32 = 0x10325476, h4: UInt32 = 0xC3D2E1F0
        var msg = message
        let bitLen = UInt64(message.count) &* 8
        msg.append(0x80)
        while msg.count % 64 != 56 { msg.append(0) }
        for i in stride(from: 56, through: 0, by: -8) { msg.append(UInt8((bitLen >> UInt64(i)) & 0xff)) }
        func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }
        var w = [UInt32](repeating: 0, count: 80)
        var chunk = 0
        while chunk < msg.count {
            for i in 0..<16 {
                let j = chunk + i * 4
                w[i] = (UInt32(msg[j]) << 24) | (UInt32(msg[j+1]) << 16) | (UInt32(msg[j+2]) << 8) | UInt32(msg[j+3])
            }
            for i in 16..<80 { w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1) }
            var a = h0, b = h1, c = h2, d = h3, e = h4
            for i in 0..<80 {
                let (f, kk): (UInt32, UInt32)
                switch i {
                case 0..<20: f = (b & c) | (~b & d); kk = 0x5A827999
                case 20..<40: f = b ^ c ^ d; kk = 0x6ED9EBA1
                case 40..<60: f = (b & c) | (b & d) | (c & d); kk = 0x8F1BBCDC
                default: f = b ^ c ^ d; kk = 0xCA62C1D6
                }
                let t = rotl(a, 5) &+ f &+ e &+ kk &+ w[i]
                e = d; d = c; c = rotl(b, 30); b = a; a = t
            }
            h0 = h0 &+ a; h1 = h1 &+ b; h2 = h2 &+ c; h3 = h3 &+ d; h4 = h4 &+ e
            chunk += 64
        }
        return bigEndianBytes([h0, h1, h2, h3, h4])
    }

    // MARK: MD5

    private static let md5s: [UInt32] = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                                         5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                                         4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                                         6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21]
    private static let md5k: [UInt32] = (0..<64).map { UInt32(truncatingIfNeeded: Int64(floor(abs(sin(Double($0 + 1))) * 4294967296))) }

    public static func md5(_ message: [UInt8]) -> [UInt8] {
        var a0: UInt32 = 0x67452301, b0: UInt32 = 0xefcdab89, c0: UInt32 = 0x98badcfe, d0: UInt32 = 0x10325476
        var msg = message
        let bitLen = UInt64(message.count) &* 8
        msg.append(0x80)
        while msg.count % 64 != 56 { msg.append(0) }
        for i in 0..<8 { msg.append(UInt8((bitLen >> UInt64(i * 8)) & 0xff)) }   // little-endian length
        func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }
        var m = [UInt32](repeating: 0, count: 16)
        var chunk = 0
        while chunk < msg.count {
            for i in 0..<16 {
                let j = chunk + i * 4
                m[i] = UInt32(msg[j]) | (UInt32(msg[j+1]) << 8) | (UInt32(msg[j+2]) << 16) | (UInt32(msg[j+3]) << 24)
            }
            var a = a0, b = b0, c = c0, d = d0
            for i in 0..<64 {
                let (f, g): (UInt32, Int)
                switch i {
                case 0..<16: f = (b & c) | (~b & d); g = i
                case 16..<32: f = (d & b) | (~d & c); g = (5 * i + 1) % 16
                case 32..<48: f = b ^ c ^ d; g = (3 * i + 5) % 16
                default: f = c ^ (b | ~d); g = (7 * i) % 16
                }
                let tmp = d; d = c; c = b
                b = b &+ rotl(a &+ f &+ md5k[i] &+ m[g], md5s[i])
                a = tmp
            }
            a0 = a0 &+ a; b0 = b0 &+ b; c0 = c0 &+ c; d0 = d0 &+ d
            chunk += 64
        }
        return littleEndianBytes([a0, b0, c0, d0])
    }

    private static func bigEndianBytes(_ words: [UInt32]) -> [UInt8] {
        var out = [UInt8](); out.reserveCapacity(words.count * 4)
        for w in words {
            out.append(UInt8((w >> 24) & 0xff)); out.append(UInt8((w >> 16) & 0xff))
            out.append(UInt8((w >> 8) & 0xff));  out.append(UInt8(w & 0xff))
        }
        return out
    }

    private static func littleEndianBytes(_ words: [UInt32]) -> [UInt8] {
        var out = [UInt8](); out.reserveCapacity(words.count * 4)
        for w in words {
            out.append(UInt8(w & 0xff));         out.append(UInt8((w >> 8) & 0xff))
            out.append(UInt8((w >> 16) & 0xff)); out.append(UInt8((w >> 24) & 0xff))
        }
        return out
    }

    // MARK: HMAC (block size 64 covers MD5/SHA-1/SHA-256)

    public static func hmac(key: [UInt8], message: [UInt8], hash: ([UInt8]) -> [UInt8], blockSize: Int = 64) -> [UInt8] {
        var k = key
        if k.count > blockSize { k = hash(k) }
        if k.count < blockSize { k += [UInt8](repeating: 0, count: blockSize - k.count) }
        let ipad = k.map { $0 ^ 0x36 }
        let opad = k.map { $0 ^ 0x5c }
        return hash(opad + hash(ipad + message))
    }

    public static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
}
