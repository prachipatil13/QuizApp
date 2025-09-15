package com.user.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * JwtUtil is a helper class that manages the entire lifecycle of JWT:
 *  - Creating tokens after authentication
 *  - Extracting data (username, roles, expiration)
 *  - Validating token integrity and expiration
 */
@Component // Marks this as a Spring-managed bean, so we can inject it anywhere
public class JwtUtil {

    // ----------------------------
    // 🔐 Secret key and expiration
    // ----------------------------
    // NOTE: In production, never hardcode. Use ENV variable or Config server.
    private final String SECRET_KEY = "u8f9vB3kL2m5x9QzR7tYw3pZs6v8e1r4u7x2q5t8v0z3c6b9n1m4k7d2s5g8h0";

    // Token expiration time = 24 hours
    private final long JWT_EXPIRATION = 1000 * 60 * 60 * 24;

    // ----------------------------
    // 📝 Extracting Data from Token
    // ----------------------------

    /**
     * Extracts username (stored as "subject") from the JWT
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts any claim from token using a resolver function.
     * Example:
     *   - extractClaim(token, Claims::getExpiration)
     *   - extractClaim(token, Claims::getSubject)
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Parses the token and retrieves all claims (payload data).
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY) // ensures only our secret can verify token
                .parseClaimsJws(token)     // parses the signed JWT
                .getBody();                // returns payload (claims)
    }

    // ----------------------------
    // 🛠 Token Generation
    // ----------------------------

    /**
     * Generates a JWT for an authenticated user.
     * Includes:
     *   - username (as subject)
     *   - user role (as custom claim)
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        // store role as extra claim (e.g., ROLE_ADMIN, ROLE_USER)
        claims.put("role", userDetails.getAuthorities().toArray()[0].toString());

        return createToken(claims, userDetails.getUsername());
    }

    /**
     * Creates a signed JWT string with claims, subject, issuedAt, and expiration.
     */
    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION);

        return Jwts.builder()
                .setClaims(claims)                 // custom claims (role, etc.)
                .setSubject(subject)               // username
                .setIssuedAt(now)                  // token issue time
                .setExpiration(expiryDate)         // token expiry time
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // sign with HMAC + secret
                .compact();                        // generate compact string
    }

    // ----------------------------
    // ✅ Token Validation
    // ----------------------------

    /**
     * Validates a token by:
     *   1. Matching username inside token with the userDetails
     *   2. Ensuring token is not expired
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);

        // valid only if username matches AND token not expired
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    /**
     * Checks if the JWT is expired.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extracts the expiration date of the token.
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}