using System.Runtime.InteropServices;

internal static class SodiumInterop
{
    [DllImport("libsodium")]
    internal static extern int crypto_sign_detached(byte[] sig, out ulong siglen, byte[] m, ulong mlen, byte[] sk);

    [DllImport("libsodium")]
    internal static extern int crypto_generichash(byte[] output, ulong outlen, byte[] input, ulong inlen, byte[] key, ulong keylen);
}
