package com.example.auth.service;

import com.example.auth.client.LDAPClient;
import com.example.auth.client.OAuth2Client;
import com.example.auth.model.CustomUserDetails;
import com.example.auth.repository.ApiKeyRepository;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class ExternalAuthenticationService {

    private final LDAPClient ldapClient;
    private final OAuth2Client oauth2Client;
    private final ApiKeyRepository apiKeyRepository;
    private final UserRepository userRepository;

    @Cacheable(value = "ldapUsers", key = "#username")
    public boolean isLDAPUser(String username) {
        return ldapClient.userExists(username);
    }

    @Cacheable(value = "oauth2Users", key = "#username")
    public boolean isOAuth2User(String username) {
        return oauth2Client.isRegisteredUser(username);
    }

    @Transactional(readOnly = true)
    public Optional<CustomUserDetails> validateApiKey(String apiKey) {
        return apiKeyRepository.findByKeyAndActiveTrue(apiKey)
                .map(key -> {
                    key.setLastUsed(new Date());
                    apiKeyRepository.save(key);
                    return CustomUserDetails.fromApiKey(key);
                });
    }

    public Optional<CustomUserDetails> authenticateLDAP(String username, String password) {
        try {
            return ldapClient.authenticate(username, password)
                    .map(ldapUser -> CustomUserDetails.builder()
                            .username(ldapUser.getUsername())
                            .email(ldapUser.getEmail())
                            .authorities(ldapUser.getGroups())
                            .authenticationMethod(AuthenticationMethod.LDAP)
                            .department(ldapUser.getDepartment())
                            .build());
        } catch (Exception e) {
            log.error("LDAP authentication failed for user: {}", username, e);
            return Optional.empty();
        }
    }

    public Optional<CustomUserDetails> authenticateOAuth2(String username, String accessToken) {
        try {
            return oauth2Client.validateToken(accessToken)
                    .filter(tokenInfo -> tokenInfo.getUsername().equals(username))
                    .map(tokenInfo -> CustomUserDetails.builder()
                            .username(tokenInfo.getUsername())
                            .email(tokenInfo.getEmail())
                            .authorities(tokenInfo.getScopes())
                            .authenticationMethod(AuthenticationMethod.OAUTH2)
                            .subscriptionLevel(tokenInfo.getSubscriptionLevel())
                            .build());
        } catch (Exception e) {
            log.error("OAuth2 authentication failed for user: {}", username, e);
            return Optional.empty();
        }
    }
}