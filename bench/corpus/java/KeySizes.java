package demo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeySizes {
    private static final int LEGACY_BITS = 1024;

    public KeyPair legacy() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(LEGACY_BITS);
        return g.generateKeyPair();
    }

    public KeyPair current(int requested) throws Exception {
        int bits = 2048;
        bits = Math.max(bits, requested);
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }
}
