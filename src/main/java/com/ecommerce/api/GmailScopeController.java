package com.ecommerce.api;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class GmailScopeController {

    private final ClientRegistrationRepository repo;

    public GmailScopeController(ClientRegistrationRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/oauth2/request-gmail-scope")
    public String addGmailScope(HttpServletRequest request, HttpSession session) {
        // Build manual authorization redirect with additional scopes
        ClientRegistration google = ((InMemoryClientRegistrationRepository)repo)
                .findByRegistrationId("google");

        String state = UUID.randomUUID().toString();
        session.setAttribute("OAUTH2_STATE_GMAIL", state);

        // Resolve the concrete redirect URI (expands {baseUrl}) from the incoming request
        String resolvedRedirect = ServletUriComponentsBuilder.fromRequest(request)
                .replacePath(request.getContextPath() + "/login/oauth2/code/" + google.getRegistrationId())
                .replaceQuery(null)
                .build()
                .toUriString();

        String encodedRedirect = URLEncoder.encode(resolvedRedirect, StandardCharsets.UTF_8);

        // build a manual URL with additional scope parameter and the resolved redirect URI
        String authUri = google.getProviderDetails().getAuthorizationUri() +
                "?response_type=code" +
                "&client_id=" + google.getClientId() +
                "&redirect_uri=" + encodedRedirect +
                "&scope=openid%20email%20profile%20https://www.googleapis.com/auth/gmail.readonly" +
                "&state=" + state +
                "&access_type=offline" +
                "&prompt=consent";

        return "redirect:" + authUri;
    }
}