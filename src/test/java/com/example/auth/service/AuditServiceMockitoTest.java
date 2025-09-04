package com.example.auth.service;

import com.example.auth.model.AuditLog;
import com.example.auth.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuditService Unit Tests with Mockito")
class AuditServiceMockitoTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private AuditService auditService;

    @BeforeEach
    void setUp() {
        // Mock RequestContextHolder
        ServletRequestAttributes attributes = mock(ServletRequestAttributes.class);
        when(attributes.getRequest()).thenReturn(request);
        RequestContextHolder.setRequestAttributes(attributes);

        // Setup request mocks
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getHeader("User-Agent")).thenReturn("Test Browser");
    }

    @Test
    @DisplayName("Should log authentication event")
    void testLogAuthentication() {
        // Act
        auditService.logAuthentication("testuser", "LOGIN_SUCCESS", "User logged in");

        // Assert - Since it's async, we need to verify with timeout
        verify(auditLogRepository, timeout(1000)).save(argThat(auditLog ->
                auditLog.getUsername().equals("testuser") &&
                        auditLog.getEventType().equals("LOGIN_SUCCESS") &&
                        auditLog.getDetails().equals("User logged in") &&
                        auditLog.getIpAddress().equals("127.0.0.1") &&
                        auditLog.getUserAgent().equals("Test Browser")
        ));
    }

    @Test
    @DisplayName("Should handle audit logging failure gracefully")
    void testAuditLoggingFailure() {
        // Arrange
        when(auditLogRepository.save(any(AuditLog.class)))
                .thenThrow(new RuntimeException("Database error"));

        // Act - Should not throw exception
        assertThatCode(() -> auditService.logAuthentication("testuser", "LOGIN_FAILED", "Failed"))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Should get user audit logs")
    void testGetUserAuditLogs() {
        // Arrange
        List<AuditLog> expectedLogs = Arrays.asList(
                AuditLog.builder().username("testuser").eventType("LOGIN_SUCCESS").build(),
                AuditLog.builder().username("testuser").eventType("LOGOUT").build()
        );
        when(auditLogRepository.findByUsername("testuser")).thenReturn(expectedLogs);

        // Act
        List<AuditLog> result = auditService.getUserAuditLogs("testuser");

        // Assert
        assertThat(result).hasSize(2);
        assertThat(result).extracting("eventType")
                .containsExactly("LOGIN_SUCCESS", "LOGOUT");
    }

    @Test
    @DisplayName("Should count failed login attempts")
    void testCountFailedLoginAttempts() {
        // Arrange
        LocalDateTime since = LocalDateTime.now().minusHours(1);
        when(auditLogRepository.countFailedLoginAttempts("testuser", since))
                .thenReturn(3L);

        // Act
        long count = auditService.countFailedLoginAttempts("testuser", since);

        // Assert
        assertThat(count).isEqualTo(3);
    }
}