package com.example.auth.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom Authentication Entry Point that handles unauthorized access attempts.
 * This component is triggered when an unauthenticated user tries to access a protected resource.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {

        log.error("Unauthorized access attempt: {} {} - Error: {}",
                request.getMethod(),
                request.getRequestURI(),
                authException.getMessage());

        // Set response status and content type
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // Add security headers
        response.setHeader("WWW-Authenticate", "Bearer realm=\"Secure API\"");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-XSS-Protection", "1; mode=block");

        // Build error response
        Map<String, Object> errorResponse = buildErrorResponse(request, authException);

        // Write response
        objectMapper.writeValue(response.getOutputStream(), errorResponse);
    }

    /**
     * Build a detailed error response based on the authentication exception type.
     */
    private Map<String, Object> buildErrorResponse(
            HttpServletRequest request,
            AuthenticationException authException) {

        Map<String, Object> error = new HashMap<>();

        // Basic error information
        error.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        error.put("status", HttpStatus.UNAUTHORIZED.value());
        error.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());
        error.put("path", request.getRequestURI());
        error.put("method", request.getMethod());

        // Determine specific error message and code based on exception type
        ErrorDetails errorDetails = determineErrorDetails(authException);
        error.put("code", errorDetails.getCode());
        error.put("message", errorDetails.getMessage());
        error.put("details", errorDetails.getDetails());

        // Add request ID for tracking (if available)
        String requestId = request.getHeader("X-Request-ID");
        if (requestId != null) {
            error.put("requestId", requestId);
        }

        // Add client information for debugging (in non-production environments)
        if (isDebugMode()) {
            Map<String, String> debugInfo = new HashMap<>();
            debugInfo.put("remoteAddress", request.getRemoteAddr());
            debugInfo.put("userAgent", request.getHeader("User-Agent"));
            debugInfo.put("referer", request.getHeader("Referer"));
            error.put("debug", debugInfo);
        }

        return error;
    }

    /**
     * Determine specific error details based on the authentication exception type.
     */
    private ErrorDetails determineErrorDetails(AuthenticationException authException) {
        if (authException instanceof BadCredentialsException) {
            return new ErrorDetails(
                    "AUTH001",
                    "Invalid credentials",
                    "The provided credentials are incorrect. Please check your username and password."
            );
        } else if (authException instanceof LockedException) {
            return new ErrorDetails(
                    "AUTH002",
                    "Account locked",
                    "Your account has been locked due to multiple failed login attempts. Please contact support."
            );
        } else if (authException instanceof DisabledException) {
            return new ErrorDetails(
                    "AUTH003",
                    "Account disabled",
                    "Your account has been disabled. Please contact support for assistance."
            );
        } else if (authException instanceof AccountExpiredException) {
            return new ErrorDetails(
                    "AUTH004",
                    "Account expired",
                    "Your account has expired. Please contact support to renew your account."
            );
        } else if (authException instanceof CredentialsExpiredException) {
            return new ErrorDetails(
                    "AUTH005",
                    "Credentials expired",
                    "Your credentials have expired. Please reset your password."
            );
        } else if (authException instanceof InsufficientAuthenticationException) {
            return new ErrorDetails(
                    "AUTH006",
                    "Insufficient authentication",
                    "Full authentication is required to access this resource."
            );
        } else if (authException.getMessage() != null &&
                authException.getMessage().toLowerCase().contains("token")) {
            return new ErrorDetails(
                    "AUTH007",
                    "Invalid or expired token",
                    "The authentication token is invalid or has expired. Please login again."
            );
        } else {
            return new ErrorDetails(
                    "AUTH000",
                    "Authentication failed",
                    "Authentication failed. Please ensure you have the correct credentials and try again."
            );
        }
    }

    /**
     * Check if the application is running in debug mode.
     */
    private boolean isDebugMode() {
        // In production, this should check the application profile or configuration
        String profile = System.getProperty("spring.profiles.active", "");
        return profile.contains("dev") || profile.contains("debug");
    }

    /**
     * Inner class to hold error details.
     */
    private static class ErrorDetails {
        private final String code;
        private final String message;
        private final String details;

        public ErrorDetails(String code, String message, String details) {
            this.code = code;
            this.message = message;
            this.details = details;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }

        public String getDetails() {
            return details;
        }
    }
}