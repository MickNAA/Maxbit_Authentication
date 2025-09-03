package com.example.auth.client;

import com.example.auth.model.LDAPUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.stereotype.Component;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class LDAPClient {

    @Value("${ldap.url}")
    private String ldapUrl;

    @Value("${ldap.base}")
    private String ldapBase;

    @Value("${ldap.username}")
    private String ldapUsername;

    @Value("${ldap.password}")
    private String ldapPassword;

    @Value("${ldap.user-search-base}")
    private String userSearchBase;

    @Value("${ldap.group-search-base}")
    private String groupSearchBase;

    private LdapTemplate ldapTemplate;

    private LdapTemplate getLdapTemplate() {
        if (ldapTemplate == null) {
            LdapContextSource contextSource = new LdapContextSource();
            contextSource.setUrl(ldapUrl);
            contextSource.setBase(ldapBase);
            contextSource.setUserDn(ldapUsername);
            contextSource.setPassword(ldapPassword);
            contextSource.afterPropertiesSet();

            ldapTemplate = new LdapTemplate(contextSource);
        }
        return ldapTemplate;
    }

    public boolean userExists(String username) {
        try {
            LdapQuery query = LdapQueryBuilder.query()
                    .base(userSearchBase)
                    .where("uid").is(username);

            List<String> results = getLdapTemplate().search(query,
                    (AttributesMapper<String>) attrs -> (String) attrs.get("uid").get());

            return !results.isEmpty();
        } catch (Exception e) {
            log.error("Error checking LDAP user existence: {}", e.getMessage());
            return false;
        }
    }

    public Optional<LDAPUser> authenticate(String username, String password) {
        try {
            // Authenticate user
            EqualsFilter filter = new EqualsFilter("uid", username);
            boolean authenticated = getLdapTemplate().authenticate(
                    userSearchBase,
                    filter.toString(),
                    password
            );

            if (!authenticated) {
                return Optional.empty();
            }

            // Get user details
            LdapQuery query = LdapQueryBuilder.query()
                    .base(userSearchBase)
                    .where("uid").is(username);

            List<LDAPUser> users = getLdapTemplate().search(query, new LDAPUserAttributesMapper());

            if (users.isEmpty()) {
                return Optional.empty();
            }

            LDAPUser user = users.get(0);

            // Get user groups
            Set<String> groups = getUserGroups(user.getDn());
            user.setGroups(groups);

            return Optional.of(user);

        } catch (Exception e) {
            log.error("LDAP authentication error: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private Set<String> getUserGroups(String userDn) {
        try {
            LdapQuery query = LdapQueryBuilder.query()
                    .base(groupSearchBase)
                    .where("member").is(userDn);

            List<String> groups = getLdapTemplate().search(query,
                    (AttributesMapper<String>) attrs -> {
                        try {
                            return (String) attrs.get("cn").get();
                        } catch (NamingException e) {
                            return null;
                        }
                    });

            return new HashSet<>(groups);
        } catch (Exception e) {
            log.error("Error getting user groups: {}", e.getMessage());
            return new HashSet<>();
        }
    }

    private static class LDAPUserAttributesMapper implements AttributesMapper<LDAPUser> {
        @Override
        public LDAPUser mapFromAttributes(Attributes attrs) throws NamingException {
            LDAPUser user = new LDAPUser();
            user.setUsername((String) attrs.get("uid").get());
            user.setEmail((String) attrs.get("mail").get());
            user.setDn(attrs.get("dn") != null ? attrs.get("dn").get().toString() : "");

            if (attrs.get("cn") != null) {
                user.setFullName((String) attrs.get("cn").get());
            }

            if (attrs.get("department") != null) {
                user.setDepartment((String) attrs.get("department").get());
            }

            return user;
        }
    }
}