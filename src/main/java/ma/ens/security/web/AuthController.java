package ma.ens.security.web;

import ma.ens.security.jwt.JwtUtil;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager,
                          UserDetailsService userDetailsService,
                          JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "Unauthorized",
                    "message", "Identifiants invalides"
            ));
        } catch (DisabledException e) {
            return ResponseEntity.status(403).body(Map.of(
                    "error", "Forbidden",
                    "message", "Compte desactive"
            ));
        }

        UserDetails user = userDetailsService.loadUserByUsername(request.username());
        String token = jwtUtil.generateToken(user.getUsername());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        body.put("username", user.getUsername());
        body.put("type", "Bearer");
        body.put("expiresIn", jwtUtil.getExpirationMillis() / 1000);
        body.put("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        return ResponseEntity.ok(body);
    }

    public record LoginRequest(@NotBlank String username, @NotBlank String password) {
    }
}