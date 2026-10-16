using Sodium;

public class Signer
{
    public byte[] Sign(byte[] message, byte[] key) => PublicKeyAuth.SignDetached(message, key);

    public byte[] Digest(byte[] data) => GenericHash.Hash(data, null, 32);
}
