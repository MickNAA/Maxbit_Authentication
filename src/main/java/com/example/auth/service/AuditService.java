package com.example.auth.service;

import com.example.auth.model.AuditLog;
import com.example.auth.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    @Async
    public void logAuthentication(String username, String eventType, String details) {
        try {
            AuditLog auditLog = AuditLog.builder()
                    .username(username)
                    .eventType(eventType)
                    .details(details)
                    .ipAddress(getClientIpAddress())
                    .userAgent(getUserAgent())
                    .timestamp(LocalDateTime.now())
                    .build();

            auditLogRepository.save(auditLog);

            log.info("Audit log: {} - {} - {}", username, eventType, details);
        } catch (Exception e) {
            log.error("Failed to save audit log", e);
        }
    }

    private String getClientIpAddress() {
        // In a real application, get this from HttpServletRequest
        return "127.0.0.1";
    }

    private String getUserAgent() {
        // In a real application, get this from HttpServletRequest headers
        return "Unknown";
    }
}