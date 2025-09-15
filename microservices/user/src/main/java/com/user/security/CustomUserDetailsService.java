package com.user.security;

import com.user.entities.Users;
import com.user.repository.UsersRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;  // Spring Security interface for loading users
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * ==================================================
 *  CUSTOM USER DETAILS SERVICE
 * ==================================================
 * - Implements Spring Security's UserDetailsService.
 * - This is used during authentication whenever a user
 *   tries to log in with a username.
 *
 * What happens:
 *  1. Spring Security calls loadUserByUsername(username).
 *  2. We query the database using UsersRepository.
 *  3. If user is found → wrap it into CustomUserDetails.
 *  4. If not found → throw UsernameNotFoundException.
 *
 * This makes Spring Security work seamlessly with
 * our custom Users entity in the DB.
 */
@Service   // Marks this as a service bean → detected by Spring for dependency injection
public class CustomUserDetailsService implements UserDetailsService {

    private final UsersRepository usersRepository;  // Repository for accessing Users table

    // Constructor injection for repository
    public CustomUserDetailsService(UsersRepository usersRepository) {
        this.usersRepository = usersRepository;
    }

    /**
     * ===========================================
     *  LOAD USER BY USERNAME (Core Authentication)
     * ===========================================
     * @param username → The username entered during login
     * @return UserDetails (Spring Security's user object)
     * @throws UsernameNotFoundException if user not found
     *
     * Flow:
     *  - Spring calls this when login happens.
     *  - We search DB using UsersRepository.findByUsername().
     *  - If user exists → wrap into CustomUserDetails and return.
     *  - Else → throw exception (Spring handles failure response).
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Look up user in DB by username
        Users user = usersRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with username: " + username));

        // Convert Users entity → CustomUserDetails (adapter for Spring Security)
        return new CustomUserDetails(user);
    }
}