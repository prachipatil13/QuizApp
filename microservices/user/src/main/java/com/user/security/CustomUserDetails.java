package com.user.security;

import com.user.entities.Users;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * ===============================================
 *  CUSTOM USER DETAILS
 * ===============================================
 * This class is an adapter between our custom "Users" entity
 * and Spring Security's "UserDetails" interface.
 *
 * Why needed?
 * - Spring Security does NOT directly understand our Users entity.
 * - It expects a UserDetails object (with methods like getUsername, getPassword, getAuthorities, etc.).
 * - This class bridges that gap → wraps our Users entity and exposes data in the way Spring expects.
 */
public class CustomUserDetails implements UserDetails {

    private final Users user;

    public CustomUserDetails(Users user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Add ROLE_ prefix dynamically
        return List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()));
    }

    @Override
    public String getPassword() {
        return user.getPassword(); // already BCrypt encoded in DB
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}