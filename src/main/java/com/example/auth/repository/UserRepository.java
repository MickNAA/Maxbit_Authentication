package com.example.auth.repository;

import com.example.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Query("SELECT u FROM User u WHERE u.accountNonLocked = false AND u.updatedAt < :threshold")
    List<User> findLockedAccountsOlderThan(LocalDateTime threshold);

    @Query("SELECT u FROM User u WHERE u.lastLogin < :threshold")
    List<User> findInactiveUsers(LocalDateTime threshold);

    @Query("SELECT u FROM User u WHERE :role MEMBER OF u.roles")
    List<User> findByRole(String role);

    @Query("SELECT u FROM User u WHERE u.department = :department")
    List<User> findByDepartment(String department);
}