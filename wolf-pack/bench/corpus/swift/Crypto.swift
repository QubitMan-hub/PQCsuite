import CryptoKit
import CommonCrypto

func seal(_ data: Data, key: SymmetricKey) throws -> Data {
    let box = try AES.GCM.seal(data, using: key)
    let signer = P256.Signing.PrivateKey()
    let agreement = Curve25519.KeyAgreement.PrivateKey()
    let mac = HMAC<SHA256>.authenticationCode(for: data, using: key)
    let legacy = Insecure.MD5.hash(data: data)
    let sealed = try ChaChaPoly.seal(data, using: key)
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    CC_SHA1(data.bytes, CC_LONG(data.count), &digest)
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048]
    return box.combined!
}
