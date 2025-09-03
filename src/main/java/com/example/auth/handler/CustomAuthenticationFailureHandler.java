package com.example.auth.handler;

import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.AuditService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Custom Authentication Failure Handler that handles failed authentication attempts.
 * Tracks failed attempts, locks accounts, and provides detailed error responses.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final AuditService auditService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Value("${security.max-login-attempts:5}")
    private int maxLoginAttempts;

    @Value("${security.lockout-duration:1800}")
    private int lockoutDuration; // in seconds

    @Value("${security.show-detailed-errors:false}")
    private boolean showDetailedErrors;

    @Value("${frontend.login-failure-redirect-url:}")
    private String failureRedirectUrl;

    @Override
    @Transactional
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {

        String username = extractUsername(request);
        log.warn("Authentication failed for user: {} - Reason: {}", username, exception.getMessage());

        // Track failed login attempt
        if (username != null && !username.isEmpty()) {
            handleFailedAttempt(username, request);
        }

        // Log authentication failure
        auditService.logAuthentication(
                username != null ? username : "Unknown",
                "LOGIN_FAILED",
                String.format("Authentication failed from IP: %s - Reason: %s",
                        getClientIpAddress(request),
                        exception.getMessage())
        );

        // Determine response type
        if (isAjaxRequest(request) || isApiRequest(request)) {
            // Return JSON error response
            handleJsonErrorResponse(request, response, exception, username);
        } else if (failureRedirectUrl != null && !failureRedirectUrl.isEmpty()) {
            // Redirect to failure URL for web application
            handleRedirectResponse(request, response, exception);
        } else {
            // Default JSON response
            handleJsonErrorResponse(request, response, exception, username);
        }
    }

    /**
     * Handle JSON error response for API/AJAX requests.
     */
    private void handleJsonErrorResponse(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception,
            String username) throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // Build error response
        Map<String, Object> errorResponse = buildErrorResponse(request, exception, username);

        // Write response
        objectMapper.writeValue(response.getOutputStream(), errorResponse);
    }

    /**
     * Handle redirect response for traditional web applications.
     */
    private void handleRedirectResponse(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) throws IOException {

        // Store error message in session or as parameter
        String errorParam = determineErrorParameter(exception);
        String redirectUrl = failureRedirectUrl + "?error=" + errorParam;

        response.sendRedirect(redirectUrl);
    }

    /**
     * Build detailed error response.
     */
    private Map<String, Object> buildErrorResponse(
            HttpServletRequest request,
            AuthenticationException exception,
            String username) {

        Map<String, Object> error = new HashMap<>();

        // Basic error information
        error.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        error.put("status", HttpStatus.UNAUTHORIZED.value());
        error.put("error", "Authentication Failed");
        error.put("path", request.getRequestURI());

        // Determine error details based on exception type
        ErrorInfo errorInfo = determineErrorInfo(exception, username);
        error.put("code", errorInfo.code);
        error.put("message", errorInfo.message);

        if (showDetailedErrors) {
            error.put("details", errorInfo.details);
            error.put("exceptionType", exception.getClass().getSimpleName());
        }

        // Add additional context
        Map<String, Object> context = new HashMap<>();
        context.put("ipAddress", getClientIpAddress(request));
        context.put("userAgent", request.getHeader("User-Agent"));
        context.put("authenticationMethod", getAuthenticationMethod(request));

        // Add account status if available
        if (username != null) {
            addAccountStatus(context, username);
        }

        error.put("context", context);

        // Add request ID for tracking
        String requestId = request.getHeader("X-Request-ID");
        if (requestId != null) {
            error.put("requestId", requestId);
        }

        return error;
    }

    /**
     * Determine error information based on exception type.
     */
    private ErrorInfo determineErrorInfo(AuthenticationException exception, String username) {
        if (exception instanceof BadCredentialsException) {
            int remainingAttempts = getRemainingAttempts(username);
            if (remainingAttempts > 0 && remainingAttempts < maxLoginAttempts) {
                return new ErrorInfo(
                        "AUTH_INVALID_CREDENTIALS",
                        "Invalid username or password",
                        String.format("You have %d attempt(s) remaining before your account is locked.",
                                remainingAttempts)
                );
            }
            return new ErrorInfo(
                    "AUTH_INVALID_CREDENTIALS",
                    "Invalid username or password",
                    "Please check your credentials and try again."
            );
        } else if (exception instanceof LockedException) {
            return new ErrorInfo(
                    "AUTH_ACCOUNT_LOCKED",
                    "Account is locked",
                    String.format("Your account has been locked due to %d failed login attempts. " +
                                    "It will be automatically unlocked after %d minutes.",
                            maxLoginAttempts, lockoutDuration / 60)
            );
        } else if (exception instanceof DisabledException) {
            return new ErrorInfo(
                    "AUTH_ACCOUNT_DISABLED",
                    "Account is disabled",
                    "Your account has been disabled. Please contact support for assistance."
            );
        } else if (exception instanceof AccountExpiredException) {
            return new ErrorInfo(
                    "AUTH_ACCOUNT_EXPIRED",
                    "Account has expired",
                    "Your account has expired. Please contact support to renew your account."
            );
        } else if (exception instanceof CredentialsExpiredException) {
            return new ErrorInfo(
                    "AUTH_CREDENTIALS_EXPIRED",
                    "Password has expired",
                    "Your password has expired. Please reset your password to continue."
            );
        } else if (exception instanceof UsernameNotFoundException) {
            // Don't reveal that the user doesn't exist for security reasons
            return new ErrorInfo(
                    "AUTH_INVALID_CREDENTIALS",
                    "Invalid username or password",
                    "Please check your credentials and try again."
            );
        } else if (exception instanceof InsufficientAuthenticationException) {
            return new ErrorInfo(
                    "AUTH_INSUFFICIENT",
                    "Additional authentication required",
                    "This resource requires additional authentication. Please complete the authentication process."
            );
        } else {
            return new ErrorInfo(
                    "AUTH_GENERAL_ERROR",
                    "Authentication failed",
                    "An error occurred during authentication. Please try again later."
            );
        }
    }

    /**
     * Handle failed login attempt - increment counter and lock if necessary.
     */
    private void handleFailedAttempt(String username, HttpServletRequest request) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            int failedAttempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(failedAttempts);

            if (failedAttempts >= maxLoginAttempts) {
                // Lock the account
                user.setAccountNonLocked(false);
                user.setLockedAt(LocalDateTime.now());

                log.warn("Account locked for user: {} after {} failed attempts from IP: {}",
                        username, failedAttempts, getClientIpAddress(request));

                // Send notification (email/SMS) about account lock
                sendAccountLockNotification(user);
            }

            userRepository.save(user);
        }
    }

    /**
     * Get remaining login attempts for a user.
     */
    private int getRemainingAttempts(String username) {
        if (username == null) {
            return maxLoginAttempts;
        }

        return userRepository.findByUsername(username)
                .map(user -> Math.max(0, maxLoginAttempts - user.getFailedLoginAttempts()))
                .orElse(maxLoginAttempts);
    }

    /**
     * Add account status information to the context.
     */
    private void addAccountStatus(Map<String, Object> context, String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            Map<String, Object> accountStatus = new HashMap<>();
            accountStatus.put("locked", !user.isAccountNonLocked());
            accountStatus.put("enabled", user.isEnabled());
            accountStatus.put("expired", !user.isAccountNonExpired());
            accountStatus.put("credentialsExpired", !user.isCredentialsNonExpired());
            accountStatus.put("failedAttempts", user.getFailedLoginAttempts());
            accountStatus.put("remainingAttempts", Math.max(0, maxLoginAttempts - user.getFailedLoginAttempts()));

            if (!user.isAccountNonLocked() && user.getLockedAt() != null) {
                LocalDateTime unlockTime = user.getLockedAt().plusSeconds(lockoutDuration);
                accountStatus.put("unlockTime", unlockTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            }

            context.put("accountStatus", accountStatus);
        });
    }

    /**
     * Send notification about account lock.
     */
    private void sendAccountLockNotification(User user) {
        // TODO: Implement email/SMS notification
        log.info("Account lock notification should be sent to user: {}", user.getEmail());
    }

    /**
     * Extract username from request.
     */
    private String extractUsername(HttpServletRequest request) {
        // Try to get from request parameter
        String username = request.getParameter("username");

        // Try to get from JSON body if not in parameters
        if (username == null) {
            try {
                // This would need proper implementation to read from request body
                // For now, returning null
                username = request.getAttribute("username") != null ?
                        request.getAttribute("username").toString() : null;
            } catch (Exception e) {
                log.debug("Could not extract username from request body");
            }
        }

        return username;
    }

    /**
     * Determine error parameter for redirect.
     */
    private String determineErrorParameter(AuthenticationException exception) {
        if (exception instanceof BadCredentialsException) {
            return "invalid";
        } else if (exception instanceof LockedException) {
            return "locked";
        } else if (exception instanceof DisabledException) {
            return "disabled";
        } else if (exception instanceof AccountExpiredException) {
            return "expired";
        } else if (exception instanceof CredentialsExpiredException) {
            return "credentials_expired";
        } else {
            return "error";
        }
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
     * Get the authentication method from request.
     */
    private String getAuthenticationMethod(HttpServletRequest request) {
        if (request.getHeader("X-API-KEY") != null) {
            return "API_KEY";
        } else if (request.getHeader("Authorization") != null) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader.startsWith("Bearer ")) {
                return "TOKEN";
            } else if (authHeader.startsWith("Basic ")) {
                return "BASIC";
            }
        }
        return "FORM";
    }

    /**
     * Extract client IP address from request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For",
                "X-Real-IP",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_FORWARDED",
                "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP",
                "HTTP_FORWARDED_FOR",
                "HTTP_FORWARDED"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                // Handle multiple IPs in X-Forwarded-For
                if (ip.contains(",")) {
                    return ip.split(",")[0].trim();
                }
                return ip;
            }
        }

        return request.getRemoteAddr();
    }

    /**
     * Inner class to hold error information.
     */
    private static class ErrorInfo {
        private final String code;
        private final String message;
        private final String details;

        public ErrorInfo(String code, String message, String details) {
            this.code = code;
            this.message = message;
            this.details = details;
        }
    }
}