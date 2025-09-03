// CustomUserDetails.java
package com.example.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

    private String username;
    private String password;
    private String email;
    private Set<String> authorities;
    private String department;
    private String subscriptionLevel;
    private AuthenticationMethod authenticationMethod;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

    public static CustomUserDetails fromApiKey(ApiKey apiKey) {
        return CustomUserDetails.builder()
                .username(apiKey.getOwner())
                .authorities(apiKey.getPermissions())
                .authenticationMethod(AuthenticationMethod.API_KEY)
                .build();
    }
}
