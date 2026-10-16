package demo;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;

public class TokenSigner {
    // Cipher.getInstance("DES") was removed in 2021
    public KeyPair keys() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    public byte[] sign(PrivateKey k, byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(k);
        s.update(data);
        return s.sign();
    }

    public byte[] encrypt(Key k, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(data);
    }

    public KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        return g.generateKeyPair();
    }
}
