package com.hostel.backend;

import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/users")
@PreAuthorize("hasRole('ADMIN')")
public class UserController {
    private final AccountRepository accounts; private final PasswordEncoder encoder;
    public UserController(AccountRepository accounts, PasswordEncoder encoder){this.accounts=accounts;this.encoder=encoder;}
    @GetMapping public List<Map<String,Object>> all(){
        return accounts.findAll().stream().map(a -> Map.<String,Object>of("id",a.getId(),"name",a.getName(),"email",a.getEmail(),"role",a.getRole())).toList();
    }
    @PostMapping public Map<String,Object> create(@RequestBody NewUser req){
        if(req.name()==null||req.name().isBlank()||req.email()==null||!req.email().contains("@")||req.password()==null||req.password().length()<8)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Enter name, valid email and password of at least 8 characters.");
        String role=req.role()==null?"":req.role().toUpperCase();
        if(!List.of("WARDEN","MESS_STAFF","STUDENT","ADMIN").contains(role)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid role.");
        String email=req.email().trim().toLowerCase();
        if(accounts.existsByEmailIgnoreCase(email)) throw new ResponseStatusException(HttpStatus.CONFLICT,"Email already registered.");
        Account a=accounts.save(new Account(req.name().trim(),email,encoder.encode(req.password()),role));
        return Map.of("id",a.getId(),"name",a.getName(),"email",a.getEmail(),"role",a.getRole());
    }
    @DeleteMapping("/{id}") public Map<String,String> delete(@PathVariable String id){
        accounts.deleteById(id); return Map.of("message","User deleted.");
    }
    public record NewUser(String name,String email,String password,String role){}
}
