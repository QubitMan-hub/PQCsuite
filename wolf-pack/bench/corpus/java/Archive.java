package util;

public final class Archive {
    byte[] seal(byte[] data, String name) throws Exception {
        String chosen = pick(name);
        log("sealing " + name);
        return DigestUtil.digest(data, "SHA-512");
    }

    byte[] fingerprint(byte[] data, String name) throws Exception {
        return DigestUtil.digest(data, name);
    }
}
