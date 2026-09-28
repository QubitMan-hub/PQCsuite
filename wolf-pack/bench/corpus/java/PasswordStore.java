package store;

public class PasswordStore {
    private final Argon2Hasher hasher = Argon2Hasher.withDefaults();

    public String hash(char[] password) {
        return hasher.hash(password);
    }

    public void check(Object key) {
        if (isRsaKey(key)) {
            throw new Argon2Exception("RSA keys are not passwords");
        }
    }

    private static boolean isRsaKey(Object key) {
        return key.toString().startsWith("-----BEGIN");
    }
}
