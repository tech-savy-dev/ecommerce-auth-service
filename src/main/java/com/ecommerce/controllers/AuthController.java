package com.ecommerce.controllers;

import com.ecommerce.services.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/v1/auth")
public class AuthController {

    private final JwtService jwtService;

    public AuthController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

        @GetMapping("/login")
    public ResponseEntity<Map<String, String>> handleOAuth2Login(@AuthenticationPrincipal OAuth2User oauthUser) {
        String email = oauthUser.getAttribute("email");
        String jwt = jwtService.generateToken(email);

        Map<String, String> response = new HashMap<>();
        response.put("email", email);
        response.put("token", jwt);

        return ResponseEntity.ok(response);
    }


}
