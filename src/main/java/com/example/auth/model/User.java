package com.example.auth.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * User entity representing application users with complete authentication tracking.
 * This entity includes security features, audit fields, and profile information.
 *
 * @author Your Name
 * @version 1.0
 * @since 2024
 */
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_username", columnList = "username", unique = true),
        @Index(name = "idx_email", columnList = "email", unique = true),
        @Index(name = "idx_department", columnList = "department"),
        @Index(name = "idx_last_login", columnList = "last_login"),
        @Index(name = "idx_locked_at", columnList = "locked_at"),
        @Index(name = "idx_created_at", columnList = "created_at")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
@ToString(exclude = {"password", "mfaSecret", "apiKeys"})
public class User {

    // ================== Primary Fields ==================

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "username", unique = true, nullable = false, length = 50)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "email", unique = true, nullable = false, length = 100)
    private String email;

    // ================== Personal Information ==================

    @Column(name = "first_name", length = 50)
    private String firstName;

    @Column(name = "last_name", length = 50)
    private String lastName;

    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    @Column(name = "profile_picture_url", length = 500)
    private String profilePictureUrl;

    @Column(name = "bio", columnDefinition = "TEXT")
    private String bio;

    @Column(name = "locale", length = 10)
    private String locale = "en_US";

    @Column(name = "timezone", length = 50)
    private String timezone = "UTC";

    // ================== Roles and Permissions ==================

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            indexes = @Index(name = "idx_user_roles", columnList = "user_id")
    )
    @Column(name = "role")
    private Set<String> roles = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "user_permissions",
            joinColumns = @JoinColumn(name = "user_id"),
            indexes = @Index(name = "idx_user_permissions", columnList = "user_id")
    )
    @Column(name = "permission")
    private Set<String> permissions = new HashSet<>();

    // ================== Organization ==================

    @Column(name = "department", length = 50)
    private String department;

    @Column(name = "subscription_level", length = 20)
    @Enumerated(EnumType.STRING)
    private SubscriptionLevel subscriptionLevel = SubscriptionLevel.BASIC;

    // ================== Account Status ==================

    @Column(name = "account_non_expired")
    private boolean accountNonExpired = true;

    @Column(name = "account_non_locked")
    private boolean accountNonLocked = true;

    @Column(name = "credentials_non_expired")
    private boolean credentialsNonExpired = true;

    @Column(name = "enabled")
    private boolean enabled = true;

    // ================== Security Tracking ==================

    @Column(name = "failed_login_attempts")
    private int failedLoginAttempts = 0;

    @Column(name = "locked_at")
    private LocalDateTime lockedAt;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "last_password_change")
    private LocalDateTime lastPasswordChange;

    @Column(name = "password_expires_at")
    private LocalDateTime passwordExpiresAt;

    // ================== Multi-Factor Authentication ==================

    @Column(name = "mfa_enabled")
    private boolean mfaEnabled = false;

    @Column(name = "mfa_secret", length = 100)
    private String mfaSecret;

    @ElementCollection
    @CollectionTable(
            name = "user_backup_codes",
            joinColumns = @JoinColumn(name = "user_id")
    )
    @Column(name = "backup_code")
    private Set<String> backupCodes = new HashSet<>();

    // ================== Email Verification ==================

    @Column(name = "email_verified")
    private boolean emailVerified = false;

    @Column(name = "email_verification_token", length = 100)
    private String emailVerificationToken;

    @Column(name = "email_verification_sent_at")
    private LocalDateTime emailVerificationSentAt;

    // ================== Password Reset ==================

    @Column(name = "password_reset_token", length = 100)
    private String passwordResetToken;

    @Column(name = "password_reset_token_expires_at")
    private LocalDateTime passwordResetTokenExpiresAt;

    // ================== OAuth2 Integration ==================

    @Column(name = "oauth2_provider", length = 20)
    private String oauth2Provider;

    @Column(name = "oauth2_id", length = 100)
    private String oauth2Id;

    // ================== Audit Fields ==================

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "created_by", length = 50)
    private String createdBy;

    @Column(name = "updated_by", length = 50)
    private String updatedBy;

    // ================== Relationships ==================

    @OneToMany(mappedBy = "owner", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private Set<ApiKey> apiKeys = new HashSet<>();

    // ================== Helper Methods ==================

    /**
     * Get all authorities including roles and permissions.
     * @return Collection of granted authorities
     */
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();

        // Add roles with ROLE_ prefix
        if (roles != null) {
            roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        }

        // Add permissions as is
        if (permissions != null) {
            permissions.forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
        }

        // Add department-based authority if present
        if (department != null && !department.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority("DEPT_" + department.toUpperCase()));
        }

        // Add subscription-based authorities
        if (subscriptionLevel != null) {
            authorities.addAll(subscriptionLevel.getAuthorities());
        }

        return authorities;
    }

    /**
     * Check if account is currently locked.
     * @return true if account is locked
     */
    public boolean isCurrentlyLocked() {
        return !accountNonLocked && lockedAt != null;
    }

    /**
     * Check if account lock has expired.
     * @param lockoutDurationSeconds Duration in seconds for account lockout
     * @return true if lock has expired
     */
    public boolean isLockExpired(int lockoutDurationSeconds) {
        if (!isCurrentlyLocked()) {
            return false;
        }

        LocalDateTime unlockTime = lockedAt.plusSeconds(lockoutDurationSeconds);
        return LocalDateTime.now().isAfter(unlockTime);
    }

    /**
     * Unlock the account and reset failed attempts.
     */
    public void unlockAccount() {
        this.accountNonLocked = true;
        this.failedLoginAttempts = 0;
        this.lockedAt = null;
    }

    /**
     * Lock the account with timestamp.
     */
    public void lockAccount() {
        this.accountNonLocked = false;
        this.lockedAt = LocalDateTime.now();
    }

    /**
     * Check if password has expired.
     * @return true if password is expired
     */
    public boolean isPasswordExpired() {
        if (passwordExpiresAt == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(passwordExpiresAt);
    }

    /**
     * Check if password reset token is valid.
     * @return true if token is still valid
     */
    public boolean isPasswordResetTokenValid() {
        if (passwordResetToken == null || passwordResetTokenExpiresAt == null) {
            return false;
        }
        return LocalDateTime.now().isBefore(passwordResetTokenExpiresAt);
    }

    /**
     * Get full name of the user.
     * @return Full name or username if name not available
     */
    public String getFullName() {
        if (firstName != null && lastName != null) {
            return firstName + " " + lastName;
        } else if (firstName != null) {
            return firstName;
        } else if (lastName != null) {
            return lastName;
        } else {
            return username;
        }
    }

    /**
     * Add a role to the user.
     * @param role Role to add
     */
    public void addRole(String role) {
        if (this.roles == null) {
            this.roles = new HashSet<>();
        }
        this.roles.add(role);
    }

    /**
     * Remove a role from the user.
     * @param role Role to remove
     */
    public void removeRole(String role) {
        if (this.roles != null) {
            this.roles.remove(role);
        }
    }

    /**
     * Add a permission to the user.
     * @param permission Permission to add
     */
    public void addPermission(String permission) {
        if (this.permissions == null) {
            this.permissions = new HashSet<>();
        }
        this.permissions.add(permission);
    }

    /**
     * Remove a permission from the user.
     * @param permission Permission to remove
     */
    public void removePermission(String permission) {
        if (this.permissions != null) {
            this.permissions.remove(permission);
        }
    }

    /**
     * Check if user has a specific role.
     * @param role Role to check
     * @return true if user has the role
     */
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    /**
     * Check if user has a specific permission.
     * @param permission Permission to check
     * @return true if user has the permission
     */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    /**
     * Increment failed login attempts.
     * @return Current number of failed attempts
     */
    public int incrementFailedAttempts() {
        this.failedLoginAttempts++;
        return this.failedLoginAttempts;
    }

    /**
     * Reset failed login attempts.
     */
    public void resetFailedAttempts() {
        this.failedLoginAttempts = 0;
    }
}

/**
 * Subscription level enumeration with associated feature authorities.
 */
enum SubscriptionLevel {
    BASIC("FEATURE_BASIC"),
    STANDARD("FEATURE_BASIC", "FEATURE_STANDARD"),
    PREMIUM("FEATURE_BASIC", "FEATURE_STANDARD", "FEATURE_ADVANCED", "FEATURE_ANALYTICS"),
    ENTERPRISE("FEATURE_BASIC", "FEATURE_STANDARD", "FEATURE_ADVANCED", "FEATURE_ANALYTICS", "FEATURE_ENTERPRISE", "FEATURE_API", "FEATURE_ADMIN");

    private final Set<SimpleGrantedAuthority> authorities;

    SubscriptionLevel(String... features) {
        this.authorities = new HashSet<>();
        for (String feature : features) {
            this.authorities.add(new SimpleGrantedAuthority(feature));
        }
    }

    public Set<SimpleGrantedAuthority> getAuthorities() {
        return new HashSet<>(authorities);
    }

    public boolean hasFeature(String feature) {
        return authorities.contains(new SimpleGrantedAuthority(feature));
    }
}