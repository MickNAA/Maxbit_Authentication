package com.example.auth.service;

import com.example.auth.model.CustomUserDetails;
import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return CustomUserDetails.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .email(user.getEmail())
                .authorities(user.getRoles().stream()
                        .map(role -> "ROLE_" + role)
                        .collect(Collectors.toSet()))
                .department(user.getDepartment())
                .subscriptionLevel(user.getSubscriptionLevel())
                .accountNonExpired(user.isAccountNonExpired())
                .accountNonLocked(user.isAccountNonLocked())
                .credentialsNonExpired(user.isCredentialsNonExpired())
                .enabled(user.isEnabled())
                .build();
    }

    @Transactional
    public void syncExternalUser(CustomUserDetails externalUser) {
        User user = userRepository.findByUsername(externalUser.getUsername())
                .orElse(new User());

        // Update user details from external source
        user.setUsername(externalUser.getUsername());
        user.setEmail(externalUser.getEmail());
        user.setDepartment(externalUser.getDepartment());
        user.setSubscriptionLevel(externalUser.getSubscriptionLevel());

        // Sync roles
        user.setRoles(externalUser.getAuthorities().stream()
                .map(auth -> auth.replace("ROLE_", ""))
                .collect(Collectors.toSet()));

        // Save or update user
        userRepository.save(user);

        log.info("Synced external user: {}", externalUser.getUsername());
    }
}