package com.example.auth.handler;

import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.AuditService;
import com.example.auth.service.JwtService;
import com.example.auth.service.RefreshTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CustomAuthenticationSuccessHandler Unit Tests with Mockito")
class CustomAuthenticationSuccessHandlerMockitoTest {

    @Mock
    private AuditService auditService;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private CustomAuthenticationSuccessHandler successHandler;

    private ObjectMapper objectMapper;
    private StringWriter stringWriter;
    private PrintWriter printWriter;
    private User testUser;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        ReflectionTestUtils.setField(successHandler, "objectMapper", objectMapper);
        ReflectionTestUtils.setField(successHandler, "jwtExpiration", 3600000L);
        ReflectionTestUtils.setField(successHandler, "cookieEnabled", false);

        stringWriter = new StringWriter();
        printWriter = new PrintWriter(stringWriter);

        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .department("IT")
                .subscriptionLevel(null)
                .lastLogin(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("Should handle successful authentication and return JWT tokens")
    void testOnAuthenticationSuccess() throws Exception {
        // Arrange
        when(authentication.getName()).thenReturn("testuser");
        when(authentication.getAuthorities()).thenReturn(Set.of(new SimpleGrantedAuthority("ROLE_USER")));
        when(jwtService.generateToken(authentication)).thenReturn("jwt-token-123");
        when(refreshTokenService.createRefreshToken("testuser")).thenReturn("refresh-token-123");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(auditService.logAuthentication(anyString(), anyString(), anyString()))
                .thenReturn(CompletableFuture.completedFuture(null));
        when(request.getHeader("Accept")).thenReturn("application/json");
        when(request.getRequestURI()).thenReturn("/api/auth/login");
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(response.getOutputStream()).thenReturn(mock(jakarta.servlet.ServletOutputStream.class));

        // Act
        successHandler.onAuthenticationSuccess(request, response, authentication);

        // Assert
        verify(response).setStatus(HttpServletResponse.SC_OK);
        verify(response).setContentType("application/json");

        // Verify user was updated
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(0);
        assertThat(savedUser.getLastLogin()).isNotNull();

        // Verify audit logging
        verify(auditService).logAuthentication(
                eq("testuser"),
                eq("LOGIN_SUCCESS"),
                contains("User logged in successfully")
        );

        // Verify tokens were generated
        verify(jwtService).generateToken(authentication);
        verify(refreshTokenService).createRefreshToken("testuser");
    }
}