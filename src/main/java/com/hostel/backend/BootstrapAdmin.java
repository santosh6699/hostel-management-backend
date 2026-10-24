package com.hostel.backend;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BootstrapAdmin {
    @Bean CommandLineRunner createBootstrapAdmin(AccountRepository accounts, PasswordEncoder encoder,
        @Value("${app.bootstrap-admin-email:}") String email,
        @Value("${app.bootstrap-admin-password:}") String password) {
        return args -> {
            if (email != null && !email.isBlank() && password != null && password.length() >= 12 &&
                !accounts.existsByEmailIgnoreCase(email.trim())) {
                accounts.save(new Account("Hostel Administrator", email.trim().toLowerCase(), encoder.encode(password), "ADMIN"));
                System.out.println("Bootstrap administrator account created for configured email.");
            } else if (email != null && !email.isBlank() && (password == null || password.length() < 12)) {
                System.err.println("Bootstrap admin not created: BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters.");
            }
        };
    }
}
