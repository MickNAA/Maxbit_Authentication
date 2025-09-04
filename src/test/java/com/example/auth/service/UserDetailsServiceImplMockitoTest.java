package com.example.auth.service;

import com.example.auth.model.CustomUserDetails;
import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserDetailsServiceImpl Unit Tests with Mockito")
class UserDetailsServiceImplMockitoTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserDetailsServiceImpl userDetailsService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .username("testuser")
                .password("encodedPassword")
                .email("test@example.com")
                .roles(Set.of("USER", "ADMIN"))
                .permissions(Set.of("READ", "WRITE"))
                .department("IT")
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();
    }

    @Test
    @DisplayName("Should load user by username successfully")
    void testLoadUserByUsername() {
        // Arrange
        when(userRepository.findByUsername("testuser"))
                .thenReturn(Optional.of(testUser));

        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Assert
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo("testuser");
        assertThat(userDetails.getPassword()).isEqualTo("encodedPassword");
        assertThat(userDetails.getAuthorities())
                .extracting("authority")
                .contains("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException for non-existent user")
    void testUserNotFound() {
        // Arrange
        when(userRepository.findByUsername("nonexistent"))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("nonexistent"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found: nonexistent");
    }

    @Test
    @DisplayName("Should sync external user successfully")
    void testSyncExternalUser() {
        // Arrange
        CustomUserDetails externalUser = CustomUserDetails.builder()
                .username("externaluser")
                .email("external@example.com")
                .authorities(Set.of("ROLE_USER"))
                .department("HR")
                .subscriptionLevel("PREMIUM")
                .build();

        when(userRepository.findByUsername("externaluser"))
                .thenReturn(Optional.empty());

        // Act
        userDetailsService.syncExternalUser(externalUser);

        // Assert
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getUsername()).isEqualTo("externaluser");
        assertThat(savedUser.getEmail()).isEqualTo("external@example.com");
        assertThat(savedUser.getDepartment()).isEqualTo("HR");
        assertThat(savedUser.getRoles()).contains("USER");
    }

    @Test
    @DisplayName("Should update existing user when syncing")
    void testSyncExistingExternalUser() {
        // Arrange
        User existingUser = User.builder()
                .id(1L)
                .username("externaluser")
                .email("old@example.com")
                .department("IT")
                .build();

        CustomUserDetails externalUser = CustomUserDetails.builder()
                .username("externaluser")
                .email("new@example.com")
                .authorities(Set.of("ROLE_ADMIN"))
                .department("HR")
                .subscriptionLevel("ENTERPRISE")
                .build();

        when(userRepository.findByUsername("externaluser"))
                .thenReturn(Optional.of(existingUser));

        // Act
        userDetailsService.syncExternalUser(externalUser);

        // Assert
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getId()).isEqualTo(1L); // Same ID
        assertThat(savedUser.getEmail()).isEqualTo("new@example.com"); // Updated
        assertThat(savedUser.getDepartment()).isEqualTo("HR"); // Updated
        assertThat(savedUser.getRoles()).contains("ADMIN"); // Updated
    }
}