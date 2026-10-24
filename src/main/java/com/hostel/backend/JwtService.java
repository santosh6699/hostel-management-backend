package com.hostel.backend;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    private final SecretKey key;
    private final long expiration;
    public JwtService(@Value("${app.jwt.secret}") String secret, @Value("${app.jwt.expiration-ms}") long expiration) {
        if (secret.getBytes(StandardCharsets.UTF_8).length < 32) throw new IllegalArgumentException("JWT_SECRET must be at least 32 bytes");
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expiration = expiration;
    }
    public String create(String email, String role, String name) {
        long now = System.currentTimeMillis();
        return Jwts.builder().subject(email).claim("role", role).claim("name", name)
            .issuedAt(new Date(now)).expiration(new Date(now + expiration)).signWith(key).compact();
    }
    public TokenData parse(String token) {
        Claims c = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
        return new TokenData(c.getSubject(), c.get("role", String.class), c.get("name", String.class));
    }
    public record TokenData(String email, String role, String name) {}
}
