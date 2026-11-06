package ma.ens.security.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/user/profile")
    public ResponseEntity<Map<String, Object>> userProfile(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Acces autorise a l'espace utilisateur",
                "username", authentication.getName(),
                "authorities", authorities(authentication),
                "stateless", true,
                "serverTime", Instant.now().toString()
        ));
    }

    @GetMapping("/admin/dashboard")
    public ResponseEntity<Map<String, Object>> adminDashboard(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Acces autorise a l'espace administrateur",
                "username", authentication.getName(),
                "authorities", authorities(authentication),
                "serverTime", Instant.now().toString()
        ));
    }

    @GetMapping("/public/info")
    public ResponseEntity<Map<String, Object>> publicInfo() {
        return ResponseEntity.ok(Map.of(
                "application", "spring-jwt-api",
                "authEndpoint", "/api/auth/login",
                "protectedEndpoints", List.of("/api/user/profile", "/api/admin/dashboard")
        ));
    }

    private List<String> authorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}