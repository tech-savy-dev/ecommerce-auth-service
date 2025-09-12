package com.ecommerce.tokens;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.*;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.*;

@Service
public class InternalJwtService {

    private final KeyPair currentKeyPair;
    private final String currentKid = "key-1"; // Manage rotation externally (DB / config)

    public InternalJwtService() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            currentKeyPair = kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public String mintForUser(String userId, java.time.Duration ttl) {
        try {
            Instant now = Instant.now();
            JWSSigner signer = new RSASSASigner(currentKeyPair.getPrivate());
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://bff.example.com")
                .subject(userId)
                .audience(List.of("internal-services"))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(ttl.toSeconds())))
                .jwtID(UUID.randomUUID().toString())
                .claim("scp", "user.read")
                .build();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(currentKid)
                .type(JOSEObjectType.JWT)
                .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(signer);
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public KeyPair getCurrentKeyPair() {
        return currentKeyPair;
    }

    public String getCurrentKid() {
        return currentKid;
    }
}