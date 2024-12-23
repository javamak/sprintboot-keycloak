package com.example.my_api_server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@EnableMethodSecurity
public class JWTSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(authz -> authz
                .requestMatchers("/**")
                .authenticated())
                // .requestMatchers("/admin")
                // .hasAuthority("ADMIN")
                // .anyRequest()
                // .authenticated())
                .oauth2ResourceServer(oauth2 -> {
                    oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(new CustomAuthenticationConverter()));

                });
        return http.build();
    }

    static class CustomAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

        public AbstractAuthenticationToken convert(Jwt jwt) {

            var userName = jwt.getClaimAsString("preferred_username");
            if ("testuser1".equals(userName)) {

                Collection<GrantedAuthority> grantedAuthorities = Stream.of("ADMIN")
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                return new JwtAuthenticationToken(jwt, grantedAuthorities);
            }

            return new JwtAuthenticationToken(jwt, Collections.emptyList());
        }
    }
}