package demo;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Keys {
    public SecretKey wrap(byte[] raw) {
        return new SecretKeySpec(raw, Algs.KEY_TYPE);
    }
}
