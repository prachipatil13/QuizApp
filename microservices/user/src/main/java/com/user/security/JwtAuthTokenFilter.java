package com.user.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;     // Holds authentication info per request
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;               // Ensures filter executes once per request

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * ==================================================
 *  JWT AUTH TOKEN FILTER
 * ==================================================
 * - A custom filter that intercepts every HTTP request.
 * - Checks for presence and validity of JWT in headers.
 * - If valid → authenticate user and set security context.
 * - If invalid/missing → reject request with error.
 *
 * Runs before controller methods are called.
 */
@Component
public class JwtAuthTokenFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;                        // Utility for token parsing/validation
    private final CustomUserDetailsService userDetailsService; // To load user details from DB

    // Constructor injection
    public JwtAuthTokenFilter(JwtUtil jwtUtil, CustomUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    /**
     * =================================================
     *  MAIN FILTER METHOD
     * =================================================
     * @param request  → incoming HTTP request
     * @param response → outgoing HTTP response
     * @param filterChain → allows request to continue in filter chain
     *
     * Steps:
     *  1. Skip authentication for /api/auth/* endpoints (login/register).
     *  2. Extract JWT from "Authorization" header.
     *  3. Validate JWT & extract username.
     *  4. Load user details and set authentication in SecurityContext.
     *  5. If token invalid/missing → send JSON error response.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getServletPath();

        // === Step 1: Skip JWT check for auth endpoints (register/login) ===
        if (path.startsWith("/api/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String username = null;

        // === Step 2: Check Authorization header ===
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7); // Extract token (remove "Bearer ")
            try {
                // Extract username from token
                username = jwtUtil.extractUsername(jwt);
            } catch (Exception e) {
                // Token invalid or expired → send error
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired JWT token");
                return;
            }
        } else {
            // No token provided → reject
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "Missing Authorization header");
            return;
        }

        // === Step 3: Validate token & authenticate user ===
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Load user details from DB
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Validate token against user
            if (jwtUtil.validateToken(jwt, userDetails)) {
                System.out.println("Validating token against user");
                // Create authentication token and set it in SecurityContext
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // ✅ Now user is considered authenticated for this request
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                // Token does not match user → reject
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
                return;
            }
        }

        // === Step 4: Continue filter chain ===
        filterChain.doFilter(request, response);
    }

    /**
     * =================================================
     *  HELPER: SEND JSON ERROR RESPONSE
     * =================================================
     * @param response → HTTP response
     * @param status   → HTTP status code (401, 403, etc.)
     * @param message  → Error description
     *
     * Builds a JSON error body like:
     *   { "status": 401, "error": "Invalid JWT token" }
     */
    private void sendError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("status", status);
        errorBody.put("error", message);

        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().write(mapper.writeValueAsString(errorBody));
    }
}