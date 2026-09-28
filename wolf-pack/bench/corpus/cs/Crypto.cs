using System.Security.Cryptography;

public static class Crypto
{
    public static RSA Keys() => RSA.Create(2048);

    public static byte[] Legacy(byte[] d)
    {
        using var h = SHA1.Create();
        return h.ComputeHash(d);
    }

    public static Aes Sym()
    {
        var a = Aes.Create();
        a.Mode = CipherMode.CBC;
        return a;
    }
}
