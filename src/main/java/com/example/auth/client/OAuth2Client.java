package com.example.auth.client;

import com.example.auth.model.OAuth2TokenInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2Client {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper;

    @Value("${security.oauth2.client.registration.google.client-id:}")
    private String googleClientId;

    @Value("${security.oauth2.client.registration.google.client-secret:}")
    private String googleClientSecret;

    @Value("${security.oauth2.client.registration.github.client-id:}")
    private String githubClientId;

    @Value("${security.oauth2.client.registration.github.client-secret:}")
    private String githubClientSecret;

    private static final String GOOGLE_TOKEN_INFO_URL = "https://oauth2.googleapis.com/tokeninfo";
    private static final String GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
    private static final String GITHUB_USER_URL = "https://api.github.com/user";

    public boolean isRegisteredUser(String email) {
        // Check if user has OAuth2 registration
        // In production, this would check against a database of OAuth2 users
        return email.endsWith("@gmail.com") || email.endsWith("@github.com");
    }

    public Optional<OAuth2TokenInfo> validateToken(String accessToken) {
        try {
            // Try Google first
            Optional<OAuth2TokenInfo> googleInfo = validateGoogleToken(accessToken);
            if (googleInfo.isPresent()) {
                return googleInfo;
            }

            // Try GitHub
            return validateGitHubToken(accessToken);

        } catch (Exception e) {
            log.error("OAuth2 token validation failed: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<OAuth2TokenInfo> validateGoogleToken(String accessToken) {
        try {
            String url = GOOGLE_TOKEN_INFO_URL + "?access_token=" + accessToken;
            ResponseEntity<Map> response = restTemplate.getForEntity(url, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> body = response.getBody();

                // Get additional user info
                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(accessToken);
                HttpEntity<String> entity = new HttpEntity<>(headers);

                ResponseEntity<Map> userResponse = restTemplate.exchange(
                        GOOGLE_USER_INFO_URL,
                        HttpMethod.GET,
                        entity,
                        Map.class
                );

                if (userResponse.getBody() != null) {
                    Map<String, Object> userInfo = userResponse.getBody();

                    OAuth2TokenInfo tokenInfo = new OAuth2TokenInfo();
                    tokenInfo.setProvider("google");
                    tokenInfo.setUsername((String) userInfo.get("email"));
                    tokenInfo.setEmail((String) userInfo.get("email"));
                    tokenInfo.setName((String) userInfo.get("name"));
                    tokenInfo.setScopes(Arrays.asList(((String) body.getOrDefault("scope", "")).split(" ")));
                    tokenInfo.setSubscriptionLevel(determineSubscriptionLevel(userInfo));

                    return Optional.of(tokenInfo);
                }
            }
        } catch (Exception e) {
            log.debug("Not a valid Google token: {}", e.getMessage());
        }

        return Optional.empty();
    }

    private Optional<OAuth2TokenInfo> validateGitHubToken(String accessToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                    GITHUB_USER_URL,
                    HttpMethod.GET,
                    entity,
                    Map.class
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> userInfo = response.getBody();

                OAuth2TokenInfo tokenInfo = new OAuth2TokenInfo();
                tokenInfo.setProvider("github");
                tokenInfo.setUsername((String) userInfo.get("login"));
                tokenInfo.setEmail((String) userInfo.get("email"));
                tokenInfo.setName((String) userInfo.get("name"));
                tokenInfo.setScopes(Arrays.asList("user:email", "read:user"));
                tokenInfo.setSubscriptionLevel(determineGitHubSubscriptionLevel(userInfo));

                return Optional.of(tokenInfo);
            }
        } catch (Exception e) {
            log.debug("Not a valid GitHub token: {}", e.getMessage());
        }

        return Optional.empty();
    }

    public String exchangeCodeForToken(String code, String provider) {
        try {
            if ("google".equalsIgnoreCase(provider)) {
                return exchangeGoogleCode(code);
            } else if ("github".equalsIgnoreCase(provider)) {
                return exchangeGitHubCode(code);
            }
        } catch (Exception e) {
            log.error("Failed to exchange code for token: {}", e.getMessage());
        }
        return null;
    }

    private String exchangeGoogleCode(String code) {
        String tokenUrl = "https://oauth2.googleapis.com/token";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", googleClientId);
        params.add("client_secret", googleClientSecret);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", "http://localhost:8080/oauth2/callback/google");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        if (response.getBody() != null) {
            return (String) response.getBody().get("access_token");
        }

        return null;
    }

    private String exchangeGitHubCode(String code) {
        String tokenUrl = "https://github.com/login/oauth/access_token";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", githubClientId);
        params.add("client_secret", githubClientSecret);

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        if (response.getBody() != null) {
            return (String) response.getBody().get("access_token");
        }

        return null;
    }

    private String determineSubscriptionLevel(Map<String, Object> userInfo) {
        // Logic to determine subscription level based on user info
        // This is a simplified example
        Boolean emailVerified = (Boolean) userInfo.get("verified_email");
        if (emailVerified != null && emailVerified) {
            return "STANDARD";
        }
        return "BASIC";
    }

    private String determineGitHubSubscriptionLevel(Map<String, Object> userInfo) {
        // Check if user has a pro account
        String plan = (String) userInfo.get("plan");
        if ("pro".equalsIgnoreCase(plan)) {
            return "PREMIUM";
        }
        return "STANDARD";
    }
}