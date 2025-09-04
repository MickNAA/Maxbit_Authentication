package com.example.auth.handler;

import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.AuditService;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CustomAuthenticationFailureHandler Unit Tests with Mockito")
class CustomAuthenticationFailureHandlerMockitoTest {

    @Mock
    private AuditService auditService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private CustomAuthenticationFailureHandler failureHandler;

    private ObjectMapper objectMapper;
    private StringWriter stringWriter;
    private PrintWriter printWriter;
    private User testUser;

    @BeforeEach
    void setUp() throws Exception {
        objectMapper = new ObjectMapper();
        ReflectionTestUtils.setField(failureHandler, "objectMapper", objectMapper);
        ReflectionTestUtils.setField(failureHandler, "maxLoginAttempts", 5);
        ReflectionTestUtils.setField(failureHandler, "lockoutDuration", 1800);
        ReflectionTestUtils.setField(failureHandler, "showDetailedErrors", true);

        stringWriter = new StringWriter();
        printWriter = new PrintWriter(stringWriter);

        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .failedLoginAttempts(0)
                .accountNonLocked(true)
                .build();
    }

    @Test
    @DisplayName("Should handle failed authentication and increment attempts")
    void testOnAuthenticationFailure() throws Exception {
        // Arrange
        BadCredentialsException exception = new BadCredentialsException("Invalid credentials");
        when(request.getParameter("username")).thenReturn("testuser");
        when(request.getHeader("Accept")).thenReturn("application/json");
        when(request.getRequestURI()).thenReturn("/api/auth/login");
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(auditService.logAuthentication(anyString(), anyString(), anyString()))
                .thenReturn(CompletableFuture.completedFuture(null));
        when(response.getOutputStream()).thenReturn(mock(jakarta.servlet.ServletOutputStream.class));

        // Act
        failureHandler.onAuthenticationFailure(request, response, exception);

        // Assert
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).setContentType("application/json");

        // Verify failed attempts were incremented
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(1);

        // Verify audit logging
        verify(auditService).logAuthentication(
                eq("testuser"),
                eq("LOGIN_FAILED"),
                contains("Authentication failed")
        );
    }

    @Test
    @DisplayName("Should lock account after max failed attempts")
    void testAccountLockoutAfterMaxAttempts() throws Exception {
        // Arrange
        testUser.setFailedLoginAttempts(4); // One more attempt will lock
        BadCredentialsException exception = new BadCredentialsException("Invalid credentials");

        when(request.getParameter("username")).thenReturn("testuser");
        when(request.getHeader("Accept")).thenReturn("application/json");
        when(request.getRequestURI()).thenReturn("/api/auth/login");
        when(request.getRemoteAddr")).thenReturn("127.0.0.1");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(auditService.logAuthentication(anyString(), anyString(), anyString()))
                .thenReturn(CompletableFuture.completedFuture(null));
        when(response.getOutputStream()).thenReturn(mock(jakarta.servlet.ServletOutputStream.class));

        // Act
        failureHandler.onAuthenticationFailure(request, response, exception);

        // Assert
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();

        assertThat(savedUser.getFailedLoginAttempts()).isEqualTo(5);
        assertThat(savedUser.isAccountNonLocked()).isFalse();
        assertThat(savedUser.getLockedAt()).isNotNull();
    }

    @Test
    @DisplayName("Should handle locked account exception")
    void testLockedAccountException() throws Exception {
        // Arrange
        LockedException exception = new LockedException("Account is locked");
        when(request.getParameter("username")).thenReturn("testuser");
        when(request.getHeader("Accept")).thenReturn("application/json");
        when(request.getRequestURI()).thenReturn("/api/auth/login");
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(auditService.logAuthentication(anyString(), anyString(), anyString()))
                .thenReturn(CompletableFuture.completedFuture(null));
        when(response.getOutputStream()).thenReturn(mock(jakarta.servlet.ServletOutputStream.class));

        // Act
        failureHandler.onAuthenticationFailure(request, response, exception);

        // Assert
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(auditService).logAuthentication(
                eq("testuser"),
                eq("LOGIN_FAILED"),
                contains("Account is locked")
        );
    }
}