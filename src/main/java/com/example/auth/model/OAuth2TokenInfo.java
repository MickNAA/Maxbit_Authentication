package com.example.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2TokenInfo {
    private String provider;
    private String username;
    private String email;
    private String name;
    private List<String> scopes;
    private String subscriptionLevel;
}