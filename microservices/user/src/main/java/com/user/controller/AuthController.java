package com.user.controller;

import com.user.entities.Users;
import com.user.repository.UsersRepository;
import com.user.security.CustomUserDetails;
import com.user.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * AuthController is responsible for handling user authentication-related requests.
 * It provides two main endpoints:
 *  1. /register → To create a new user account
 *  2. /login    → To authenticate an existing user and generate JWT token
 */
@RestController                          // Marks this class as a REST API controller
@RequestMapping("/api/auth")             // All endpoints inside this controller will start with "/api/auth"
public class AuthController {

    // === Dependencies injected via constructor ===
    private final UsersRepository usersRepository;          // Handles database operations for Users entity
    private final PasswordEncoder passwordEncoder;          // Used to encode (hash) user passwords before saving
    private final AuthenticationManager authenticationManager; // Manages authentication process
    private final JwtUtil jwtUtil;                          // Utility class for generating JWT tokens

    // === Constructor injection (recommended for immutability & testing) ===
    public AuthController(UsersRepository usersRepository,
                          PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager,
                          JwtUtil jwtUtil) {
        this.usersRepository = usersRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    /**
     * ======================
     *  USER REGISTRATION
     * ======================
     * Endpoint: POST /api/auth/register
     *
     * @param user The user details sent from client (username, email, password)
     * @return ResponseEntity with success or error message
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Users user) {
        // Check if username already exists
        if (usersRepository.existsByUsername(user.getUsername())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username already exists"));
        }

        // Check if email already exists
        if (usersRepository.existsByEmail(user.getEmail())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already exists"));
        }

        // Encrypt (hash) password before saving to database
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // Assign default role as "USER"
        user.setRole("USER");

        // Save the new user in the database
        usersRepository.save(user);

        // Return success message
        return ResponseEntity.ok(Map.of("message", "User registered successfully"));
    }

    /**
     * ======================
     *  USER LOGIN
     * ======================
     * Endpoint: POST /api/auth/login
     *
     * @param loginRequest A map containing "username" and "password" from client
     * @return ResponseEntity with JWT token + user details
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginRequest) {
        System.out.println("user request for login");
        // Step 1: Authenticate user using AuthenticationManager
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.get("username"), // Username from request
                        loginRequest.get("password")  // Password from request
                )
        );

        // Step 2: Retrieve authenticated user details
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        // Step 3: Generate JWT token for the authenticated user
        String token = jwtUtil.generateToken(userDetails);
        System.out.println("user token generated");
        // Step 4: Return user details along with token
        return ResponseEntity.ok(Map.of(
                "username", userDetails.getUsername(),
                "role", userDetails.getAuthorities().toArray()[0].toString(), // Extract role
                "token", token
        ));
    }
}