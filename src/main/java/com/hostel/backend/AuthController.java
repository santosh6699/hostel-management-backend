package com.hostel.backend;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AccountRepository accounts;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    public AuthController(AccountRepository accounts, PasswordEncoder encoder, JwtService jwt) {
        this.accounts=accounts; this.encoder=encoder; this.jwt=jwt;
    }
    @PostMapping("/register")
    public Map<String,Object> register(@RequestBody RegisterRequest req) {
        if (req.name()==null || req.name().isBlank() || req.email()==null || !req.email().contains("@") ||
            req.password()==null || req.password().length()<8) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Enter a name, valid email and password of at least 8 characters.");
        }
        String email=req.email().trim().toLowerCase();
        if (accounts.existsByEmailIgnoreCase(email)) throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered.");
        Account account=accounts.save(new Account(req.name().trim(), email, encoder.encode(req.password()), "STUDENT"));
        return session(account);
    }
    @PostMapping("/login")
    public Map<String,Object> login(@RequestBody LoginRequest req) {
        Account account=accounts.findByEmailIgnoreCase(req.email()==null?"":req.email().trim())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password."));
        if (req.password()==null || !encoder.matches(req.password(), account.getPassword()))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password.");
        return session(account);
    }
    @GetMapping("/me")
    public Map<String,Object> me(org.springframework.security.core.Authentication auth) {
        Account a=accounts.findByEmailIgnoreCase(auth.getName())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        return publicUser(a);
    }
    private Map<String,Object> session(Account a) {
        var out=new java.util.LinkedHashMap<String,Object>();
        out.put("token",jwt.create(a.getEmail(),a.getRole(),a.getName()));
        out.putAll(publicUser(a));
        return out;
    }
    private Map<String,Object> publicUser(Account a) {
        return Map.of("id",a.getId(),"name",a.getName(),"email",a.getEmail(),"role",a.getRole());
    }
    public record RegisterRequest(String name, String email, String password) {}
    public record LoginRequest(String email, String password) {}
}
