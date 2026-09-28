package demo;

import java.security.MessageDigest;

public class Hasher {
    private static final String DIGEST_ALG = "SHA-1";
    private static final String BANNER = "AES";

    public byte[] id(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance(DIGEST_ALG);
        return md.digest(b);
    }

    public void hello() {
        System.out.println(BANNER);
    }
}
