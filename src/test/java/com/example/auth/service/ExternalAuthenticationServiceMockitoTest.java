package com.example.auth.service;

import com.example.auth.client.LDAPClient;
import com.example.auth.client.OAuth2Client;
import com.example.auth.model.ApiKey;
import com.example.auth.model.CustomUserDetails;
import com.example.auth.model.LDAPUser;
import com.example.auth.model.OAuth2TokenInfo;
import com.example.auth.repository.ApiKeyRepository;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ExternalAuthenticationService Unit Tests with Mockito")
class ExternalAuthenticationServiceMockitoTest {

    @Mock
    private LDAPClient ldapClient;

    @Mock
    private OAuth2Client oauth2Client;

    @Mock
    private ApiKeyRepository apiKeyRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private ExternalAuthenticationService externalAuthService;

    private ApiKey validApiKey;
    private LDAPUser ldapUser;
    private OAuth2TokenInfo oauth2TokenInfo;

    @BeforeEach
    void setUp() {
        validApiKey = ApiKey.builder()
                .key("test-api-key")
                .owner("testuser")
                .permissions(Set.of("API_ACCESS", "READ"))
                .active(true)
                .expiresAt(LocalDateTime.now().plusDays(30))
                .lastUsed(new java.util.Date())
                .build();

        ldapUser = new LDAPUser();
        ldapUser.setUsername("ldapuser");
        ldapUser.setEmail("ldap@company.com");
        ldapUser.setDepartment("IT");
        ldapUser.setGroups(Set.of("ADMIN", "USER"));

        oauth2TokenInfo = new OAuth2TokenInfo();
        oauth2TokenInfo.setUsername("oauth2user");
        oauth2TokenInfo.setEmail("oauth@gmail.com");
        oauth2TokenInfo.setScopes(Arrays.asList("email", "profile"));
        oauth2TokenInfo.setSubscriptionLevel("PREMIUM");
    }

    @Test
    @DisplayName("Should validate API key successfully")
    void testValidateApiKey() {
        // Arrange
        when(apiKeyRepository.findByKeyAndActiveTrue("test-api-key"))
                .thenReturn(Optional.of(validApiKey));

        // Act
        Optional<CustomUserDetails> result = externalAuthService.validateApiKey("test-api-key");

        // Assert
        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("testuser");

        // Verify the API key last used time was updated
        verify(apiKeyRepository).save(any(ApiKey.class));
    }

    @Test
    @DisplayName("Should return empty for invalid API key")
    void testInvalidApiKey() {
        // Arrange
        when(apiKeyRepository.findByKeyAndActiveTrue("invalid-key"))
                .thenReturn(Optional.empty());

        // Act
        Optional<CustomUserDetails> result = externalAuthService.validateApiKey("invalid-key");

        // Assert
        assertThat(result).isEmpty();
        verify(apiKeyRepository, never()).save(any());
    }

    @Test
    @DisplayName("Should authenticate with LDAP successfully")
    void testAuthenticateLDAP() {
        // Arrange
        when(ldapClient.authenticate("ldapuser", "password"))
                .thenReturn(Optional.of(ldapUser));

        // Act
        Optional<CustomUserDetails> result = externalAuthService.authenticateLDAP("ldapuser", "password");

        // Assert
        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("ldapuser");
        assertThat(result.get().getDepartment()).isEqualTo("IT");
        assertThat(result.get().getAuthorities()).contains("ADMIN", "USER");
    }

    @Test
    @DisplayName("Should handle LDAP authentication failure")
    void testLDAPAuthenticationFailure() {
        // Arrange
        when(ldapClient.authenticate("ldapuser", "wrongpassword"))
                .thenReturn(Optional.empty());

        // Act
        Optional<CustomUserDetails> result = externalAuthService.authenticateLDAP("ldapuser", "wrongpassword");

        // Assert
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("Should authenticate with OAuth2 successfully")
    void testAuthenticateOAuth2() {
        // Arrange
        when(oauth2Client.validateToken("oauth-token"))
                .thenReturn(Optional.of(oauth2TokenInfo));

        // Act
        Optional<CustomUserDetails> result = externalAuthService.authenticateOAuth2("oauth2user", "oauth-token");

        // Assert
        assertThat(result).isPresent();
        assertThat(result.get().getUsername()).isEqualTo("oauth2user");
        assertThat(result.get().getSubscriptionLevel()).isEqualTo("PREMIUM");
    }

    @Test
    @DisplayName("Should check if user is LDAP user")
    void testIsLDAPUser() {
        // Arrange
        when(ldapClient.userExists("ldapuser")).thenReturn(true);
        when(ldapClient.userExists("regularuser")).thenReturn(false);

        // Act & Assert
        assertThat(externalAuthService.isLDAPUser("ldapuser")).isTrue();
        assertThat(externalAuthService.isLDAPUser("regularuser")).isFalse();
    }

    @Test
    @DisplayName("Should check if user is OAuth2 user")
    void testIsOAuth2User() {
        // Arrange
        when(oauth2Client.isRegisteredUser("oauth@gmail.com")).thenReturn(true);
        when(oauth2Client.isRegisteredUser("regular@example.com")).thenReturn(false);

        // Act & Assert
        assertThat(externalAuthService.isOAuth2User("oauth@gmail.com")).isTrue();
        assertThat(externalAuthService.isOAuth2User("regular@example.com")).isFalse();
    }
}