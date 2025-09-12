package com.ecommerce.controllers;

import com.ecommerce.tokens.InternalJwtService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

@RestController
public class JwksController {

    private final InternalJwtService internalJwtService;

    public JwksController(InternalJwtService internalJwtService) {
        this.internalJwtService = internalJwtService;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> jwks() {
        RSAPublicKey pub = (RSAPublicKey) internalJwtService.getCurrentKeyPair().getPublic();
        String n = base64Url(pub.getModulus());
        String e = base64Url(pub.getPublicExponent());
        Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "kid", internalJwtService.getCurrentKid(),
                "alg", "RS256",
                "use", "sig",
                "n", n,
                "e", e
        );
        return Map.of("keys", java.util.List.of(jwk));
    }

    private String base64Url(BigInteger bi) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(toUnsignedBytes(bi));
    }

    private byte[] toUnsignedBytes(BigInteger bi) {
        byte[] bytes = bi.toByteArray();
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return bytes;
    }
}
