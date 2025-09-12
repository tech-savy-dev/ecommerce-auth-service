package com.ecommerce.controllers;

import com.ecommerce.tokens.InternalJwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.Map;

@RestController
public class ProductProxyController {

    private final RestClient restClient;
    private final InternalJwtService internalJwtService;
    private final String productBase;
    private static final Logger log = LoggerFactory.getLogger(ProductProxyController.class);

    public ProductProxyController(InternalJwtService internalJwtService,
                                  @Value("${app.downstream.product.base-url}") String productBase) {
        this.internalJwtService = internalJwtService;
        // Normalize: remove any trailing slashes so we can safely concatenate full incoming path
        this.productBase = productBase.replaceAll("/+$", "");
        this.restClient = RestClient.builder().build();
    }

    @RequestMapping(value = "/api/v1/product/**")
    public ResponseEntity<?> proxy(HttpServletRequest request,
                                   HttpSession session,
                                   @RequestBody(required = false) byte[] body,
                                   @RequestHeader HttpHeaders incoming,
                                   HttpMethod method) {
        String userId = (String) session.getAttribute("USER_ID");
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "unauthorized"));
        }
        String token = ensureInternalJwt(session, userId);
        String fullPath = request.getRequestURI(); // e.g. /api/v1/product/list
        // Simply forward the same path to downstream (assumes product service exposes identical prefix)
        String target = productBase + fullPath; // productBase already stripped of trailing slash
        if (log.isDebugEnabled()) {
            log.debug("Proxying {} {} -> {}", method, fullPath, target);
        }

        RestClient.RequestBodySpec spec = restClient.method(method).uri(target)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header("X-User-Id", userId);

        if (incoming.getFirst(HttpHeaders.ACCEPT) != null) {
            spec = spec.header(HttpHeaders.ACCEPT, incoming.getFirst(HttpHeaders.ACCEPT));
        }
        if (incoming.getFirst(HttpHeaders.CONTENT_TYPE) != null) {
            spec = spec.header(HttpHeaders.CONTENT_TYPE, incoming.getFirst(HttpHeaders.CONTENT_TYPE));
        }

        ResponseEntity<byte[]> downstream;
        try {
            downstream = (body != null && body.length > 0 ? spec.body(body) : spec)
                    .retrieve()
                    .toEntity(byte[].class);
        } catch (org.springframework.web.client.HttpStatusCodeException ex) {
            // Surface downstream status & body (if any) to caller to aid debugging (avoid swallowing 4xx/5xx)
            HttpHeaders errorHeaders = new HttpHeaders();
            if (ex.getResponseHeaders() != null && ex.getResponseHeaders().getContentType() != null) {
                errorHeaders.setContentType(ex.getResponseHeaders().getContentType());
            }
            byte[] responseBody = ex.getResponseBodyAsByteArray();
            if (log.isWarnEnabled()) {
                log.warn("Downstream call failed: status={} path={} msg={}", ex.getStatusCode(), fullPath, ex.getMessage());
            }
            return new ResponseEntity<>(responseBody, errorHeaders, ex.getStatusCode());
        }

        HttpHeaders out = new HttpHeaders();
        if (downstream.getHeaders().getContentType() != null) {
            out.setContentType(downstream.getHeaders().getContentType());
        }
        return new ResponseEntity<>(downstream.getBody(), out, downstream.getStatusCode());
    }

    private String ensureInternalJwt(HttpSession session, String userId) {
        Long exp = (Long) session.getAttribute("INTERNAL_JWT_EXP");
        String token = (String) session.getAttribute("INTERNAL_JWT");
        long now = System.currentTimeMillis();
        if (token != null && exp != null && exp - now > 60_000) {
            return token;
        }
        String newToken = internalJwtService.mintForUser(userId, Duration.ofMinutes(15));
        session.setAttribute("INTERNAL_JWT", newToken);
        session.setAttribute("INTERNAL_JWT_EXP", System.currentTimeMillis() + Duration.ofMinutes(15).toMillis());
        return newToken;
    }
}