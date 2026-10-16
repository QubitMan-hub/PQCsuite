package util;

import java.security.MessageDigest;

public final class DigestUtil {
    public static byte[] digest(byte[] data, String algorithm) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(data);
    }
}
