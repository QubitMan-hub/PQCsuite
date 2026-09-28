package com.example.payments;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CardVault {
    private final SecretKeySpec key;

    public CardVault(byte[] secret) {
        this.key = new SecretKeySpec(secret, "AES");
    }

    public byte[] fingerprint(String pan) throws Exception {
        return MessageDigest.getInstance("MD5").digest(pan.getBytes("UTF-8"));
    }

    public byte[] seal(byte[] record) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(record);
    }
}
