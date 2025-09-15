package com.user.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SecurityConfig configures Spring Security for authentication and authorization.
 * It includes password encoding, JWT filter, and endpoint access rules.
 */
@Configuration
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;  // Load user details from DB
    private final JwtAuthTokenFilter jwtAuthTokenFilter;        // Filter to validate JWTs

    public SecurityConfig(CustomUserDetailsService userDetailsService,
                          JwtAuthTokenFilter jwtAuthTokenFilter) {
        this.userDetailsService = userDetailsService;
        this.jwtAuthTokenFilter = jwtAuthTokenFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers("/api/auth/**").permitAll()
                        // Only ADMIN can access /api/admin/**
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        // Only USER can access /api/user/**
                        .requestMatchers("/api/user/**").hasRole("USER")
                        // All others require authentication
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        http.addFilterBefore(jwtAuthTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    // AuthenticationManager bean for authenticating users
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        System.out.println("user auntheticated");
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailsService) // use custom UserDetailsService
                .passwordEncoder(passwordEncoder())     // use BCrypt password encoder
                .and()
                .build();

    }

    // Password encoder bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
