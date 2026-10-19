package demo;

import java.security.MessageDigest;
import java.security.spec.MGF1ParameterSpec;

public class Digests {
    public MessageDigest forBits(int bits) throws Exception {
        return MessageDigest.getInstance("SHA-" + bits);
    }

    public MGF1ParameterSpec mgf1() {
        return new MGF1ParameterSpec("SHA-256");
    }
}
