package com.ecommerce.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class UserAccountService {

    private final Map<String, UserAccount> store = new ConcurrentHashMap<>();

    public record UserAccount(String id, String email, Instant createdAt, Map<String,Object> attrs) {}

    public UserAccount upsertOAuthUser(String email, Map<String,Object> attrs) {
        return store.compute(email.toLowerCase(), (k,v) -> {
            if (v == null) {
                return new UserAccount(email.toLowerCase(), email, Instant.now(), attrs);
            }
            return new UserAccount(v.id(), v.email(), v.createdAt(), attrs);
        });
    }
}