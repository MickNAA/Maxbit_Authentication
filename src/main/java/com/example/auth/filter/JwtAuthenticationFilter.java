package com.example.auth.filter;

import com.example.auth.service.AuthenticationService;
import com.example.auth.service.JwtService;
import com.example.auth.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT Authentication Filter that processes JWT tokens in the Authorization header.
 * This filter runs once per request and validates JWT tokens for protected endpoints.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;
    private final AuthenticationService authenticationService;

    // Endpoints that should be excluded from JWT authentication
    private static final List<String> EXCLUDED_PATHS = List.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh",
            "/api/public",
            "/swagger-ui",
            "/v3/api-docs",
            "/actuator/health"
    );

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            // Extract JWT token from request
            String jwt = extractJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Check if token is blacklisted (for logout functionality)
                if (authenticationService.isTokenBlacklisted(jwt)) {
                    log.warn("Attempted to use blacklisted token");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\": \"Token has been invalidated\"}");
                    return;
                }

                // Validate token and extract username
                if (!jwtService.isTokenExpired(jwt)) {
                    String username = jwtService.extractUsername(jwt);

                    if (username != null) {
                        // Load user details
                        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                        // Validate token with user details
                        if (jwtService.validateToken(jwt, userDetails.getUsername())) {
                            // Create authentication token
                            UsernamePasswordAuthenticationToken authToken =
                                    new UsernamePasswordAuthenticationToken(
                                            userDetails,
                                            null,
                                            userDetails.getAuthorities()
                                    );

                            // Set additional details from the request
                            authToken.setDetails(
                                    new WebAuthenticationDetailsSource().buildDetails(request)
                            );

                            // Set authentication in security context
                            SecurityContextHolder.getContext().setAuthentication(authToken);

                            log.debug("JWT authentication successful for user: {}", username);

                            // Add user info to request attributes for downstream use
                            request.setAttribute("username", username);
                            request.setAttribute("authorities", userDetails.getAuthorities());
                        } else {
                            log.warn("JWT validation failed for user: {}", username);
                        }
                    }
                } else {
                    log.debug("JWT token is expired");
                }
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication: {}", e.getMessage());
            // Clear security context on error
            SecurityContextHolder.clearContext();
        }

        // Continue filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from the request.
     * Supports both Authorization header and query parameter.
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        // Try to extract from Authorization header first
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        // Fallback to query parameter (useful for WebSocket connections)
        String token = request.getParameter("token");
        if (StringUtils.hasText(token)) {
            return token;
        }

        return null;
    }

    /**
     * Determine if this filter should be applied to the current request.
     * Skip JWT validation for public endpoints.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return EXCLUDED_PATHS.stream().anyMatch(path::startsWith);
    }

    /**
     * Handle authentication errors by setting appropriate response.
     */
    private void handleAuthenticationError(
            HttpServletResponse response,
            String message) throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write(
                String.format("{\"error\": \"Authentication failed\", \"message\": \"%s\"}", message)
        );
    }
}