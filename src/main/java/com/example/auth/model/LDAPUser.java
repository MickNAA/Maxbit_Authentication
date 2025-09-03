package com.example.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LDAPUser {
    private String username;
    private String email;
    private String fullName;
    private String dn;
    private String department;
    private Set<String> groups;
}