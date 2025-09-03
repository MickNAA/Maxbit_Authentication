package com.example.auth.filter;

import com.example.auth.dto.LoginRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Custom Authentication Filter that supports multiple authentication methods:
 * - Username/Password (JSON body)
 * - API Key (Header)
 * - OAuth2 Token (Header)
 * - LDAP credentials
 */
@Slf4j
public class CustomAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Constructor that sets up the request matchers for authentication endpoints.
     */
    public CustomAuthenticationFilter() {
        super(new OrRequestMatcher(
                new AntPathRequestMatcher("/api/auth/login", "POST"),
                new AntPathRequestMatcher("/api/auth/custom", "POST"),
                new AntPathRequestMatcher("/api/auth/api-key", "POST")
        ));
    }

    /**
     * Constructor with custom request matcher.
     */
    public CustomAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    /**
     * Constructor with custom authentication manager.
     */
    public CustomAuthenticationFilter(
            AuthenticationManager authenticationManager,
            RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException, IOException {

        log.debug("Attempting authentication for request: {} {}",
                request.getMethod(), request.getRequestURI());

        // Determine authentication method and extract credentials
        AuthenticationRequest authRequest = extractAuthenticationRequest(request);

        if (authRequest == null) {
            throw new BadCredentialsException("No valid authentication credentials provided");
        }

        log.debug("Authentication method detected: {}", authRequest.getMethod());

        // Create Spring Security authentication token
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        authRequest.getPrincipal(),
                        authRequest.getCredentials()
                );

        // Add additional details to the authentication token
        Map<String, Object> details = new HashMap<>();
        details.put("method", authRequest.getMethod());
        details.put("ipAddress", getClientIpAddress(request));
        details.put("userAgent", request.getHeader("User-Agent"));
        authToken.setDetails(details);

        // Delegate to authentication manager
        return this.getAuthenticationManager().authenticate(authToken);
    }

    /**
     * Extract authentication request from HTTP request.
     * Supports multiple authentication methods.
     */
    private AuthenticationRequest extractAuthenticationRequest(HttpServletRequest request)
            throws IOException {

        // Check for API Key authentication
        String apiKey = request.getHeader("X-API-KEY");
        if (StringUtils.hasText(apiKey)) {
            return new AuthenticationRequest("", "ApiKey " + apiKey, "API_KEY");
        }

        // Check for Bearer token (OAuth2/JWT)
        String authHeader = request.getHeader("Authorization");
        if (StringUtils.hasText(authHeader)) {
            if (authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                // Determine if it's OAuth2 or JWT based on token structure
                String method = isOAuth2Token(token) ? "OAUTH2" : "JWT";
                return new AuthenticationRequest("", authHeader, method);
            }
        }

        // Check for custom token header
        String customToken = request.getHeader("X-Auth-Token");
        if (StringUtils.hasText(customToken)) {
            return new AuthenticationRequest("", "Bearer " + customToken, "CUSTOM_TOKEN");
        }

        // Try to parse JSON body for username/password
        if ("POST".equalsIgnoreCase(request.getMethod()) &&
                request.getContentType() != null &&
                request.getContentType().contains("application/json")) {

            try {
                String body = request.getReader().lines()
                        .collect(Collectors.joining(System.lineSeparator()));

                LoginRequest loginRequest = objectMapper.readValue(body, LoginRequest.class);

                if (loginRequest.getUsername() != null && loginRequest.getPassword() != null) {
                    // Determine if it's LDAP or regular authentication
                    String method = isLdapUser(loginRequest.getUsername()) ? "LDAP" : "USERNAME_PASSWORD";
                    return new AuthenticationRequest(
                            loginRequest.getUsername(),
                            loginRequest.getPassword(),
                            method
                    );
                }
            } catch (Exception e) {
                log.error("Failed to parse JSON authentication request: {}", e.getMessage());
            }
        }

        // Fallback to form parameters
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
            String method = isLdapUser(username) ? "LDAP" : "USERNAME_PASSWORD";
            return new AuthenticationRequest(username, password, method);
        }

        return null;
    }

    /**
     * Successful authentication handler.
     */
    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult) throws IOException, ServletException {

        log.info("Authentication successful for user: {}", authResult.getName());

        // Set authentication in security context
        SecurityContextHolder.getContext().setAuthentication(authResult);

        // Continue with the filter chain for API key or token-based auth
        if (isApiRequest(request)) {
            chain.doFilter(request, response);
        } else {
            // For login endpoint, delegate to success handler
            if (getSuccessHandler() != null) {
                getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
            } else {
                // Default success response
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType("application/json");

                Map<String, Object> result = new HashMap<>();
                result.put("authenticated", true);
                result.put("username", authResult.getName());
                result.put("authorities", authResult.getAuthorities());

                objectMapper.writeValue(response.getOutputStream(), result);
            }
        }
    }

    /**
     * Failed authentication handler.
     */
    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {

        log.warn("Authentication failed: {}", failed.getMessage());

        // Clear security context
        SecurityContextHolder.clearContext();

        // Delegate to failure handler if configured
        if (getFailureHandler() != null) {
            getFailureHandler().onAuthenticationFailure(request, response, failed);
        } else {
            // Default failure response
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");

            Map<String, Object> error = new HashMap<>();
            error.put("authenticated", false);
            error.put("error", "Authentication failed");
            error.put("message", failed.getMessage());
            error.put("timestamp", System.currentTimeMillis());

            objectMapper.writeValue(response.getOutputStream(), error);
        }
    }

    /**
     * Check if the token appears to be an OAuth2 token.
     */
    private boolean isOAuth2Token(String token) {
        // Simple heuristic: OAuth2 tokens are typically shorter and don't have dots
        // JWT tokens have three parts separated by dots
        return !token.contains(".") || token.split("\\.").length != 3;
    }

    /**
     * Check if the username is an LDAP user.
     */
    private boolean isLdapUser(String username) {
        // Simple check: LDAP users typically have email format or contain domain
        return username.contains("@") || username.contains("\\");
    }

    /**
     * Check if this is an API request (not a login request).
     */
    private boolean isApiRequest(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.contains("/login") && !path.contains("/auth");
    }

    /**
     * Extract client IP address from request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(xRealIp)) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * Inner class to hold authentication request details.
     */
    private static class AuthenticationRequest {
        private final String principal;
        private final String credentials;
        private final String method;

        public AuthenticationRequest(String principal, String credentials, String method) {
            this.principal = principal;
            this.credentials = credentials;
            this.method = method;
        }

        public String getPrincipal() {
            return principal;
        }

        public String getCredentials() {
            return credentials;
        }

        public String getMethod() {
            return method;
        }
    }
}