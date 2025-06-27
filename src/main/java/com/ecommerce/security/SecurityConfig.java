package com.ecommerce.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filter(HttpSecurity http) throws Exception {
        http.csrf(Customizer.withDefaults())
          .authorizeHttpRequests(auth -> auth
              .requestMatchers("/v1/auth/**").permitAll()
              .anyRequest().authenticated()
          ).oauth2Login(oauth -> oauth
                        .defaultSuccessUrl("/v1/auth/token", true)
                );

        return http.build();
    }


}
