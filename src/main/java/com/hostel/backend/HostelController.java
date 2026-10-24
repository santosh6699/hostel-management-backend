package com.hostel.backend;

import java.util.*;
import org.bson.types.ObjectId;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api")
public class HostelController {
    private final MongoTemplate mongo;
    public HostelController(MongoTemplate mongo){this.mongo=mongo;}

    private static final Map<String,String> COLLECTIONS=Map.of(
        "students","students","rooms","rooms","fees","fees","mess","mess","complaints","complaints");

    private String collection(String module){
        String c=COLLECTIONS.get(module);
        if(c==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Unknown module");
        return c;
    }
    @GetMapping("/{module:students|rooms|fees|mess|complaints}")
    public List<Map<String,Object>> getAll(@PathVariable String module,
        org.springframework.security.core.Authentication auth){
        authorizeRead(module, auth.getAuthorities().stream().map(a->a.getAuthority()).toList());
        List<Map> docs=mongo.findAll(Map.class,collection(module));
        List<Map<String,Object>> out=new ArrayList<>();
        for(Map doc:docs){ Map<String,Object> m=new LinkedHashMap<>(); doc.forEach((k,v)->m.put(String.valueOf(k),v)); out.add(m); }
        return out;
    }
    @PostMapping("/{module:students|rooms|fees|mess|complaints}")
    public Map<String,Object> create(@PathVariable String module,@RequestBody Map<String,Object> body,
        org.springframework.security.core.Authentication auth){
        authorizeWrite(module, auth.getAuthorities().stream().map(a->a.getAuthority()).toList());
        body.remove("_id"); body.remove("id");
        return mongo.save(body,collection(module));
    }
    @PutMapping("/{module:students|rooms|fees|mess|complaints}/{id}")
    public Map<String,Object> update(@PathVariable String module,@PathVariable String id,@RequestBody Map<String,Object> body,
        org.springframework.security.core.Authentication auth){
        authorizeWrite(module, auth.getAuthorities().stream().map(a->a.getAuthority()).toList());
        if(!ObjectId.isValid(id)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid record id");
        body.remove("_id"); body.remove("id");
        Update u=new Update(); body.forEach(u::set);
        mongo.updateFirst(Query.query(Criteria.where("_id").is(new ObjectId(id))),u,collection(module));
        Map<String,Object> result=mongo.findById(new ObjectId(id),Map.class,collection(module));
        if(result==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Record not found");
        return result;
    }
    @DeleteMapping("/{module:students|rooms|fees|mess|complaints}/{id}")
    public Map<String,String> delete(@PathVariable String module,@PathVariable String id,
        org.springframework.security.core.Authentication auth){
        authorizeWrite(module, auth.getAuthorities().stream().map(a->a.getAuthority()).toList());
        if(!ObjectId.isValid(id)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid record id");
        mongo.remove(Query.query(Criteria.where("_id").is(new ObjectId(id))),collection(module));
        return Map.of("message","Record deleted");
    }
    @GetMapping("/reports/summary")
    @PreAuthorize("hasAnyRole('ADMIN','WARDEN')")
    public Map<String,Object> summary(){
        long students=mongo.getCollection("students").countDocuments();
        long rooms=mongo.getCollection("rooms").countDocuments();
        long fees=mongo.getCollection("fees").countDocuments();
        long complaints=mongo.getCollection("complaints").countDocuments(new org.bson.Document("status",new org.bson.Document("$ne","Resolved")));
        return Map.of("students",students,"rooms",rooms,"fees",fees,"pendingComplaints",complaints);
    }
    private void authorizeRead(String module,List<String> roles){
        boolean ok=switch(module){
            case "students","fees","complaints" -> has(roles,"ADMIN","WARDEN","STUDENT");
            case "rooms" -> has(roles,"ADMIN","WARDEN");
            case "mess" -> has(roles,"ADMIN","WARDEN","STUDENT","MESS_STAFF");
            default -> false;
        };
        if(!ok) throw new ResponseStatusException(HttpStatus.FORBIDDEN,"You do not have permission to view this module.");
    }
    private void authorizeWrite(String module,List<String> roles){
        boolean ok=switch(module){
            case "students","rooms","fees" -> has(roles,"ADMIN","WARDEN");
            case "mess" -> has(roles,"ADMIN","WARDEN","MESS_STAFF");
            case "complaints" -> has(roles,"ADMIN","WARDEN","STUDENT");
            default -> false;
        };
        if(!ok) throw new ResponseStatusException(HttpStatus.FORBIDDEN,"You do not have permission to modify this module.");
    }
    private boolean has(List<String> roles,String... allowed){return Arrays.stream(allowed).anyMatch(r->roles.contains("ROLE_"+r));}
}
