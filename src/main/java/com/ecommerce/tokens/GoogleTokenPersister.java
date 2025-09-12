package com.ecommerce.tokens;

import org.springframework.stereotype.Repository;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class GoogleTokenPersister {

    // DO NOT keep key inline; put in KMS/Secrets Manager
    private static final byte[] KEY = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
    private final Map<String, StoredToken> store = new ConcurrentHashMap<>();

    public record StoredToken(String userId, String encRefreshToken,
                              Instant issuedAt, Instant expiresAt, String provider) {}

    public void saveOrUpdate(String userId, String refreshToken,
                             Instant issuedAt, Instant expiresAt, String provider) {
        try {
            String enc = encrypt(refreshToken);
            store.put(userId, new StoredToken(userId, enc, issuedAt, expiresAt, provider));
        } catch (Exception e) {
            throw new RuntimeException("Encrypt failure", e);
        }
    }

    public String getRefreshToken(String userId) {
        var st = store.get(userId);
        if (st == null) return null;
        try {
            return decrypt(st.encRefreshToken);
        } catch (Exception e) {
            throw new RuntimeException("Decrypt failure", e);
        }
    }

    private String encrypt(String raw) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        return java.util.Base64.getEncoder().encodeToString(c.doFinal(raw.getBytes(StandardCharsets.UTF_8)));
    }

    private String decrypt(String enc) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        return new String(c.doFinal(java.util.Base64.getDecoder().decode(enc)), StandardCharsets.UTF_8);
    }
}