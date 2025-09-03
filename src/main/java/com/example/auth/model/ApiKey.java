package com.example.auth.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Set;

@Entity
@Table(name = "api_keys")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "api_key", unique = true, nullable = false)
    private String key;

    @Column(name = "owner", nullable = false)
    private String owner;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "api_key_permissions")
    private Set<String> permissions;

    @Column(name = "active")
    private boolean active = true;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "last_used")
    private Date lastUsed;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}