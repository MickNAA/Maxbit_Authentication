package com.example.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenValidationService {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    public boolean validateToken(String token) {
        try {
            // Check if token is blacklisted
            if (authenticationService.isTokenBlacklisted(token)) {
                log.warn("Token is blacklisted: {}", token.substring(0, 20) + "...");
                return false;
            }

            // Check if token is expired
            if (jwtService.isTokenExpired(token)) {
                log.warn("Token is expired");
                return false;
            }

            // Additional validation logic can be added here
            return true;

        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        return jwtService.extractUsername(token);
    }
}