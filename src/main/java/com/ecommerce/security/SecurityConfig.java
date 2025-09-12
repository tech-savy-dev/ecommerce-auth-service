package com.ecommerce.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.*;

import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
        SecurityFilterChain filterChain(HttpSecurity http,
                                                                        OAuth2SuccessHandler successHandler) throws Exception {

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/internal/**", "/logout")
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/me", "/oauth2/**", "/login/**", "/health", "/.well-known/jwks.json","/logout").permitAll()
                        .requestMatchers("/api/v1/product/**").authenticated()
                        .requestMatchers(HttpMethod.GET, "/public/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth -> oauth
                        .successHandler(successHandler)
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutRequestMatcher(request -> 
                            "/logout".equals(request.getRequestURI()) && 
                            ("GET".equals(request.getMethod()) || "POST".equals(request.getMethod()))
                        )
                        .deleteCookies("APPSESSION", "INTERNAL_JWT", "POST_LOGIN")
                        .invalidateHttpSession(true)
                        .logoutSuccessHandler(jsonLogoutSuccessHandler())
                );

        return http.build();
    }

        private LogoutSuccessHandler jsonLogoutSuccessHandler() {
                return (request, response, authentication) -> {
                        response.setContentType("application/json");
                        response.setCharacterEncoding("UTF-8");
                        response.getWriter().write("{\"loggedOut\":true}");
                };
        }

    // For dev; in prod, prefer same-origin deployment of SPA + BFF to drop CORS.
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of("http://localhost:3000"));
        cfg.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        cfg.setAllowedHeaders(List.of("*"));
        cfg.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", cfg);
        return src;
    }
}