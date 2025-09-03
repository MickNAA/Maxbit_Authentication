package com.example.auth.handler;

import com.example.auth.dto.TokenResponse;
import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.AuditService;
import com.example.auth.service.JwtService;
import com.example.auth.service.RefreshTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Custom Authentication Success Handler that handles successful authentication.
 * Generates JWT tokens and returns authentication response.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuditService auditService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Value("${jwt.cookie.enabled:false}")
    private boolean cookieEnabled;

    @Value("${jwt.cookie.secure:true}")
    private boolean secureCookie;

    @Value("${jwt.cookie.http-only:true}")
    private boolean httpOnlyCookie;

    @Value("${jwt.cookie.same-site:Strict}")
    private String sameSiteCookie;

    @Value("${jwt.expiration:3600000}")
    private long jwtExpiration;

    @Value("${frontend.success-redirect-url:}")
    private String successRedirectUrl;

    @Override
    @Transactional
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        String username = authentication.getName();
        log.info("Authentication successful for user: {}", username);

        // Update user's last login time and reset failed attempts
        updateUserLoginInfo(username);

        // Generate tokens
        String accessToken = jwtService.generateToken(authentication);
        String refreshToken = refreshTokenService.createRefreshToken(username);

        // Log authentication success
        auditService.logAuthentication(
                username,
                "LOGIN_SUCCESS",
                String.format("User logged in successfully from IP: %s", getClientIpAddress(request))
        );

        // Determine response type based on request
        if (isAjaxRequest(request) || isApiRequest(request)) {
            // Return JSON response for AJAX/API requests
            handleJsonResponse(request, response, authentication, accessToken, refreshToken);
        } else if (cookieEnabled) {
            // Set cookies and redirect for web application
            handleCookieResponse(response, authentication, accessToken, refreshToken);
        } else {
            // Default JSON response
            handleJsonResponse(request, response, authentication, accessToken, refreshToken);
        }

        // Clear authentication attributes
        clearAuthenticationAttributes(request);
    }

    /**
     * Handle JSON response for API/AJAX requests.
     */
    private void handleJsonResponse(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            String accessToken,
            String refreshToken) throws IOException {

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // Build response
        Map<String, Object> responseBody = buildSuccessResponse(
                authentication,
                accessToken,
                refreshToken,
                request
        );

        // Write response
        objectMapper.writeValue(response.getOutputStream(), responseBody);
    }

    /**
     * Handle cookie-based authentication for web applications.
     */
    private void handleCookieResponse(
            HttpServletResponse response,
            Authentication authentication,
            String accessToken,
            String refreshToken) throws IOException {

        // Create access token cookie
        Cookie accessTokenCookie = createSecureCookie("access_token", accessToken);
        accessTokenCookie.setMaxAge((int) (jwtExpiration / 1000)); // Convert to seconds
        response.addCookie(accessTokenCookie);

        // Create refresh token cookie
        Cookie refreshTokenCookie = createSecureCookie("refresh_token", refreshToken);
        refreshTokenCookie.setMaxAge(86400 * 7); // 7 days
        response.addCookie(refreshTokenCookie);

        // Create user info cookie (non-sensitive data)
        Cookie userInfoCookie = new Cookie("user_info", authentication.getName());
        userInfoCookie.setPath("/");
        userInfoCookie.setMaxAge((int) (jwtExpiration / 1000));
        response.addCookie(userInfoCookie);

        // Redirect to success URL
        if (successRedirectUrl != null && !successRedirectUrl.isEmpty()) {
            response.sendRedirect(successRedirectUrl);
        } else {
            response.sendRedirect("/dashboard");
        }
    }

    /**
     * Build the success response body.
     */
    private Map<String, Object> buildSuccessResponse(
            Authentication authentication,
            String accessToken,
            String refreshToken,
            HttpServletRequest request) {

        Map<String, Object> response = new HashMap<>();

        // Token information
        TokenResponse tokenResponse = TokenResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtExpiration)
                .username(authentication.getName())
                .build();

        response.put("token", tokenResponse.getToken());
        response.put("refreshToken", tokenResponse.getRefreshToken());
        response.put("tokenType", tokenResponse.getTokenType());
        response.put("expiresIn", tokenResponse.getExpiresIn());

        // User information
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", authentication.getName());
        userInfo.put("authorities", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        // Add additional user details if available
        userRepository.findByUsername(authentication.getName()).ifPresent(user -> {
            userInfo.put("email", user.getEmail());
            userInfo.put("department", user.getDepartment());
            userInfo.put("subscriptionLevel", user.getSubscriptionLevel());
            userInfo.put("lastLogin", user.getLastLogin());
        });

        response.put("user", userInfo);

        // Authentication metadata
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("authenticatedAt", LocalDateTime.now().toString());
        metadata.put("authenticationMethod", getAuthenticationMethod(request));
        metadata.put("ipAddress", getClientIpAddress(request));
        response.put("metadata", metadata);

        // Success message
        response.put("message", "Authentication successful");
        response.put("status", "success");

        return response;
    }

    /**
     * Update user's login information.
     */
    private void updateUserLoginInfo(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            user.setLastLogin(LocalDateTime.now());
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
        });
    }

    /**
     * Create a secure cookie with appropriate settings.
     */
    private Cookie createSecureCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(httpOnlyCookie);
        cookie.setSecure(secureCookie);

        // Set SameSite attribute (requires servlet 5.0+)
        if (sameSiteCookie != null && !sameSiteCookie.isEmpty()) {
            cookie.setAttribute("SameSite", sameSiteCookie);
        }

        return cookie;
    }

    /**
     * Check if the request is an AJAX request.
     */
    private boolean isAjaxRequest(HttpServletRequest request) {
        String xRequestedWith = request.getHeader("X-Requested-With");
        return "XMLHttpRequest".equals(xRequestedWith);
    }

    /**
     * Check if the request is an API request.
     */
    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        String contentType = request.getHeader("Content-Type");

        return (acceptHeader != null && acceptHeader.contains("application/json")) ||
                (contentType != null && contentType.contains("application/json")) ||
                request.getRequestURI().startsWith("/api/");
    }

    /**
     * Get the authentication method used.
     */
    private String getAuthenticationMethod(HttpServletRequest request) {
        // Check various headers to determine authentication method
        if (request.getHeader("X-API-KEY") != null) {
            return "API_KEY";
        } else if (request.getHeader("Authorization") != null) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader.startsWith("Bearer ")) {
                return "TOKEN";
            }
        }
        return "USERNAME_PASSWORD";
    }

    /**
     * Extract client IP address from request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}