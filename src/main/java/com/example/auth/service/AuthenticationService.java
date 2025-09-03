package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.TokenResponse;
import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final AuditService auditService;

    // Blacklisted tokens (in production, use Redis)
    private final Map<String, LocalDateTime> blacklistedTokens = new ConcurrentHashMap<>();

    @Transactional
    public TokenResponse authenticate(LoginRequest request) {
        try {
            // Perform authentication
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            // Update last login time
            User user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() -> new BadCredentialsException("User not found"));

            user.setLastLogin(LocalDateTime.now());
            user.setFailedLoginAttempts(0); // Reset failed attempts on successful login
            userRepository.save(user);

            // Generate tokens
            String accessToken = jwtService.generateToken(authentication);
            String refreshToken = refreshTokenService.createRefreshToken(user.getUsername());

            // Audit successful login
            auditService.logAuthentication(
                    request.getUsername(),
                    "LOGIN_SUCCESS",
                    "User logged in successfully"
            );

            return TokenResponse.builder()
                    .token(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtService.getExpirationTime())
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .build();

        } catch (AuthenticationException e) {
            // Handle failed login
            handleFailedLogin(request.getUsername());

            // Audit failed login
            auditService.logAuthentication(
                    request.getUsername(),
                    "LOGIN_FAILED",
                    e.getMessage()
            );

            throw new BadCredentialsException("Invalid credentials", e);
        }
    }

    @Transactional
    public TokenResponse refreshToken(String refreshTokenHeader) {
        String refreshToken = extractToken(refreshTokenHeader);

        // Validate refresh token
        String username = refreshTokenService.validateRefreshToken(refreshToken);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        // Generate new tokens
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                username, null, user.getAuthorities()
        );

        String newAccessToken = jwtService.generateToken(authentication);
        String newRefreshToken = refreshTokenService.createRefreshToken(username);

        // Invalidate old refresh token
        refreshTokenService.deleteRefreshToken(refreshToken);

        // Audit token refresh
        auditService.logAuthentication(username, "TOKEN_REFRESH", "Token refreshed successfully");

        return TokenResponse.builder()
                .token(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getExpirationTime())
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }

    public void logout(String tokenHeader) {
        String token = extractToken(tokenHeader);

        // Add token to blacklist
        blacklistedTokens.put(token, LocalDateTime.now().plusHours(24));

        // Extract username from token for audit
        String username = jwtService.extractUsername(token);

        // If it's a refresh token, delete it
        try {
            refreshTokenService.deleteRefreshToken(token);
        } catch (Exception e) {
            log.debug("Token is not a refresh token: {}", e.getMessage());
        }

        // Audit logout
        auditService.logAuthentication(username, "LOGOUT", "User logged out successfully");

        // Clean up expired tokens from blacklist
        cleanupBlacklist();
    }

    public boolean isTokenBlacklisted(String token) {
        cleanupBlacklist();
        return blacklistedTokens.containsKey(token);
    }

    private void handleFailedLogin(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            // Lock account after 5 failed attempts
            if (attempts >= 5) {
                user.setAccountNonLocked(false);
                log.warn("Account locked for user: {} after {} failed attempts", username, attempts);
            }

            userRepository.save(user);
        });
    }

    private String extractToken(String tokenHeader) {
        if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
            return tokenHeader.substring(7);
        }
        throw new BadCredentialsException("Invalid token format");
    }

    private void cleanupBlacklist() {
        LocalDateTime now = LocalDateTime.now();
        blacklistedTokens.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
    }
}