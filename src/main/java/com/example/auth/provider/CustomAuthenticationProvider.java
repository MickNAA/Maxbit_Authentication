package com.example.auth.provider;

import com.example.auth.model.AuthenticationMethod;
import com.example.auth.model.CustomUserDetails;
import com.example.auth.service.ExternalAuthenticationService;
import com.example.auth.service.TokenValidationService;
import com.example.auth.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Custom Authentication Provider that supports multiple authentication mechanisms:
 * - Username/Password
 * - Token-based (JWT/API Key)
 * - LDAP
 * - OAuth2
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsServiceImpl userDetailsService;
    private final ExternalAuthenticationService externalAuthService;
    private final TokenValidationService tokenValidationService;
    private final PasswordEncoder passwordEncoder;

    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String API_KEY_PREFIX = "ApiKey ";

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String principal = authentication.getName();
        String credentials = authentication.getCredentials().toString();

        log.debug("Attempting authentication for principal: {}", principal);

        try {
            // Determine authentication method
            AuthenticationMethod method = determineAuthenticationMethod(principal, credentials);

            switch (method) {
                case TOKEN:
                    return authenticateWithToken(credentials);
                case API_KEY:
                    return authenticateWithApiKey(credentials);
                case LDAP:
                    return authenticateWithLDAP(principal, credentials);
                case OAUTH2:
                    return authenticateWithOAuth2(principal, credentials);
                case USERNAME_PASSWORD:
                default:
                    return authenticateWithUsernamePassword(principal, credentials);
            }
        } catch (Exception e) {
            log.error("Authentication failed for principal: {}", principal, e);
            throw new BadCredentialsException("Authentication failed", e);
        }
    }

    private AuthenticationMethod determineAuthenticationMethod(String principal, String credentials) {
        if (credentials.startsWith(TOKEN_PREFIX)) {
            return AuthenticationMethod.TOKEN;
        } else if (credentials.startsWith(API_KEY_PREFIX)) {
            return AuthenticationMethod.API_KEY;
        } else if (principal.contains("@") && principal.contains(".")) {
            // Check if it's an LDAP or OAuth2 authentication
            if (externalAuthService.isLDAPUser(principal)) {
                return AuthenticationMethod.LDAP;
            } else if (externalAuthService.isOAuth2User(principal)) {
                return AuthenticationMethod.OAUTH2;
            }
        }
        return AuthenticationMethod.USERNAME_PASSWORD;
    }

    private Authentication authenticateWithUsernamePassword(String username, String password) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        return createSuccessAuthentication(userDetails);
    }

    private Authentication authenticateWithToken(String token) {
        String actualToken = token.substring(TOKEN_PREFIX.length());

        if (!tokenValidationService.validateToken(actualToken)) {
            throw new BadCredentialsException("Invalid or expired token");
        }

        String username = tokenValidationService.getUsernameFromToken(actualToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        return createSuccessAuthentication(userDetails);
    }

    private Authentication authenticateWithApiKey(String apiKey) {
        String actualKey = apiKey.substring(API_KEY_PREFIX.length());

        Optional<CustomUserDetails> userDetails = externalAuthService.validateApiKey(actualKey);
        if (userDetails.isEmpty()) {
            throw new BadCredentialsException("Invalid API key");
        }

        return createSuccessAuthentication(userDetails.get());
    }

    private Authentication authenticateWithLDAP(String username, String password) {
        Optional<CustomUserDetails> ldapUser = externalAuthService.authenticateLDAP(username, password);

        if (ldapUser.isEmpty()) {
            throw new BadCredentialsException("LDAP authentication failed");
        }

        // Sync user data with local database if needed
        userDetailsService.syncExternalUser(ldapUser.get());

        return createSuccessAuthentication(ldapUser.get());
    }

    private Authentication authenticateWithOAuth2(String username, String accessToken) {
        Optional<CustomUserDetails> oauthUser = externalAuthService.authenticateOAuth2(username, accessToken);

        if (oauthUser.isEmpty()) {
            throw new BadCredentialsException("OAuth2 authentication failed");
        }

        // Sync user data with local database
        userDetailsService.syncExternalUser(oauthUser.get());

        return createSuccessAuthentication(oauthUser.get());
    }

    private Authentication createSuccessAuthentication(UserDetails userDetails) {
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

        // Add additional authorities based on business logic if needed
        Set<GrantedAuthority> enhancedAuthorities = new HashSet<>(authorities);
        enhancedAuthorities.addAll(getAdditionalAuthorities(userDetails));

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(),
                null,
                enhancedAuthorities
        );

        // Add additional details
        Map<String, Object> details = new HashMap<>();
        details.put("authenticationMethod", determineAuthenticationMethodFromUser(userDetails));
        details.put("authenticationTime", new Date());
        details.put("userDetails", userDetails);
        authToken.setDetails(details);

        log.info("Successfully authenticated user: {}", userDetails.getUsername());

        return authToken;
    }

    private Collection<? extends GrantedAuthority> getAdditionalAuthorities(UserDetails userDetails) {
        Set<GrantedAuthority> additionalAuthorities = new HashSet<>();

        // Add role-based authorities
        if (userDetails instanceof CustomUserDetails) {
            CustomUserDetails customUser = (CustomUserDetails) userDetails;

            // Add department-based authorities
            if (customUser.getDepartment() != null) {
                additionalAuthorities.add(new SimpleGrantedAuthority("DEPT_" + customUser.getDepartment().toUpperCase()));
            }

            // Add feature-based authorities based on subscription level
            if (customUser.getSubscriptionLevel() != null) {
                switch (customUser.getSubscriptionLevel()) {
                    case "PREMIUM":
                        additionalAuthorities.add(new SimpleGrantedAuthority("FEATURE_ADVANCED"));
                        additionalAuthorities.add(new SimpleGrantedAuthority("FEATURE_ANALYTICS"));
                    case "STANDARD":
                        additionalAuthorities.add(new SimpleGrantedAuthority("FEATURE_BASIC"));
                        break;
                }
            }
        }

        return additionalAuthorities;
    }

    private String determineAuthenticationMethodFromUser(UserDetails userDetails) {
        if (userDetails instanceof CustomUserDetails) {
            return ((CustomUserDetails) userDetails).getAuthenticationMethod().name();
        }
        return AuthenticationMethod.USERNAME_PASSWORD.name();
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}