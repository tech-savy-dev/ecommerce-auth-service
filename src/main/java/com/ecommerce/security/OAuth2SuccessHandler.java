package com.ecommerce.security;

import com.ecommerce.tokens.GoogleTokenPersister;
import com.ecommerce.tokens.InternalJwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

/**
 * Handles post-OAuth2 login:
 *  - Validates verified email
 *  - Upserts local user
 *  - Persists refresh token
 *  - Establishes HTTP session (stateful phase)
 *  - Issues internal JWT (short-lived)
 *  - Sets a marker cookie so SPA can trigger /auth/me
 */
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final OAuth2AuthorizedClientService clientService;
    private final UserAccountService userAccountService;
    private final GoogleTokenPersister googleTokenPersister;
    private final InternalJwtService internalJwtService;

    private static final String POST_LOGIN_COOKIE = "POST_LOGIN";
    private static final int POST_LOGIN_COOKIE_TTL_SECONDS = 60;

    public OAuth2SuccessHandler(OAuth2AuthorizedClientService clientService,
                                UserAccountService userAccountService,
                                GoogleTokenPersister googleTokenPersister,
                                InternalJwtService internalJwtService) {
        this.clientService = clientService;
        this.userAccountService = userAccountService;
        this.googleTokenPersister = googleTokenPersister;
        this.internalJwtService = internalJwtService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        if (!(authentication instanceof OAuth2AuthenticationToken oauth)) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unexpected authentication type");
            return;
        }

        String regId = oauth.getAuthorizedClientRegistrationId();
        OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(regId, oauth.getName());
        if (client == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Authorized client missing");
            return;
        }

        OAuth2User principal = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attrs = principal.getAttributes();

        String email = extractEmail(attrs);
        boolean emailVerified = isEmailVerified(attrs);

        if (email == null || email.isBlank()) {
            response.sendRedirect("/login?error=email_missing");
            return;
        }
        if (!emailVerified) {
            response.sendRedirect("/login?error=email_not_verified");
            return;
        }

        // Upsert local user record
        var user = userAccountService.upsertOAuthUser(email, attrs);

        // Persist refresh token (if present)
        OAuth2RefreshToken refreshToken = client.getRefreshToken();
        if (refreshToken != null) {
            googleTokenPersister.saveOrUpdate(
                    user.id(),
                    refreshToken.getTokenValue(),
                    refreshToken.getIssuedAt(),
                    refreshToken.getExpiresAt(),
                    regId
            );
        }

        // Session (stateful phase).
        HttpSession session = request.getSession(true);
        session.setAttribute("USER_ID", user.id());
        session.setAttribute("USER_EMAIL", user.email());

    // Mint internal JWT (not exposed to browser). Cache in session for BFF use.
    String internalJwt = internalJwtService.mintForUser(
        user.id(),
        Duration.ofMinutes(15)
    );
    session.setAttribute("INTERNAL_JWT", internalJwt);
    session.setAttribute("INTERNAL_JWT_EXP", System.currentTimeMillis() + Duration.ofMinutes(15).toMillis());
    addPostLoginMarkerCookie(response);

        // Optionally use query param instead of marker cookie:
        response.sendRedirect("http://localhost:3000/login?loggedIn=1");
    }

    // Removed cookie exposure of INTERNAL_JWT; token now server-side only.

    private void addPostLoginMarkerCookie(HttpServletResponse response) {
        Cookie marker = new Cookie(POST_LOGIN_COOKIE, "1");
        marker.setHttpOnly(false);
        marker.setSecure(false); // true in prod HTTPS
        marker.setPath("/");
        marker.setMaxAge(POST_LOGIN_COOKIE_TTL_SECONDS);
        response.addCookie(marker);
    }

    private String extractEmail(Map<String, Object> attrs) {
        Object e = attrs.get("email");
        if (e instanceof String s && !s.isBlank()) return s;
        for (String alt : new String[]{"preferred_username", "upn"}) {
            Object v = attrs.get(alt);
            if (v instanceof String sv && !sv.isBlank()) return sv;
        }
        return null;
    }

    private boolean isEmailVerified(Map<String, Object> attrs) {
        Object v = attrs.get("email_verified");
        if (v instanceof Boolean b) return b;
        if (v instanceof String s) return "true".equalsIgnoreCase(s) || "1".equals(s);
        return false;
    }
}