using System.Security.Cryptography;

public class Kdf
{
    public byte[] Tag(byte[] key, byte[] data)
    {
        using var mac = new HMACSHA512(key);
        return mac.ComputeHash(data);
    }

    public byte[] Agree(ECDiffieHellmanPublicKey peer)
    {
        using var ecdh = new ECDiffieHellmanCng();
        return ecdh.DeriveKeyMaterial(peer);
    }
}
