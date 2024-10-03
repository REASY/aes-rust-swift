import CryptoKit
import Foundation

enum EncryptionError: Error {
    case invalidKeyLength
    case invalidIVLength
    case encryptionFailed
}

extension Data {
    var asHex: String {
        return reduce("") {$0 + String(format: "%02x", $1)}
    }
}

@available(macOS 10.15, *)
func timeToEncrypt(
    string: String,
    key: Data,
    iv: Data,
    iterations: UInt32)-> Result<Void, EncryptionError>  {
    let symmetricKey = SymmetricKey(data: key)
    guard symmetricKey.bitCount == 128 else {
        return .failure(.invalidKeyLength)
    }
    guard iv.count == 16 else {
        return .failure(.invalidIVLength)
    }

    let dataToEncrypt = Data(string.utf8)
    var total_len: Int = 0;

    let startTime = CFAbsoluteTimeGetCurrent()
    for _ in 0..<iterations {
        do {
            let sealedBox = try AES.GCM.seal(dataToEncrypt, using: symmetricKey, nonce: AES.GCM.Nonce(data: iv))
            total_len += sealedBox.ciphertext.count + sealedBox.tag.count
            // print(sealedBox.ciphertext.asHex)
            // print(sealedBox.tag.asHex)
        } catch {
            return .failure(.encryptionFailed)
        }
    }
    let duration = CFAbsoluteTimeGetCurrent() - startTime
    print(String(format: "AES128 GSM run %d times took %f seconds. total_len dummy value is %d", iterations, duration, total_len))
    return .success(())
}

let key = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
let iv = Data([0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00])
let data = "Benchmarking AES encryption in Rust"
let iterations: UInt32 = 10_000_000

if #available(macOS 10.15, *) {
    timeToEncrypt(string:data, key:key, iv:iv, iterations:iterations)
}