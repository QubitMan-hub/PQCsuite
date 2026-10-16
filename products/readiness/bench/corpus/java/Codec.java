package demo;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;

public class Codec {
    public String fingerprint(byte[] data) {
        return DigestUtils.sha256Hex(data);
    }

    public byte[] legacy(byte[] data) {
        return DigestUtils.getDigest(MessageDigestAlgorithms.MD5).digest(data);
    }

    public byte[] any(String name, byte[] data) {
        return DigestUtils.getDigest(name).digest(data);
    }
}
