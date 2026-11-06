package ma.ens.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import ma.ens.security.jwt.JwtUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class JwtUtilTest {

    private static final String SECRET = "MySuperSecretKeyForJwtAuthentication123456";

    private final JwtUtil jwtUtil = new JwtUtil(SECRET, 3_600_000L);

    @Test
    @DisplayName("Le token genere contient trois parties")
    void generatedTokenHasThreeParts() {
        String token = jwtUtil.generateToken("admin");

        assertThat(token).isNotBlank();
        assertThat(token.split("\\.")).hasSize(3);
    }

    @Test
    @DisplayName("Le username est extrait du token")
    void usernameCanBeExtracted() {
        String token = jwtUtil.generateToken("admin");

        assertThat(jwtUtil.extractUsername(token)).isEqualTo("admin");
    }

    @Test
    @DisplayName("Le token genere est valide")
    void generatedTokenIsValid() {
        assertThat(jwtUtil.validateToken(jwtUtil.generateToken("user"))).isTrue();
    }

    @Test
    @DisplayName("Un token altere est refuse")
    void tamperedTokenIsInvalid() {
        String token = jwtUtil.generateToken("admin");
        String tampered = token.substring(0, token.length() - 3) + "abc";

        assertThat(jwtUtil.validateToken(tampered)).isFalse();
    }

    @Test
    @DisplayName("Un token signe avec un autre secret est refuse")
    void tokenSignedWithAnotherKeyIsInvalid() {
        String foreign = Jwts.builder()
                .setSubject("admin")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor("UneAutreCleSecreteVraimentTresLonguePourHS256!!".getBytes()),
                        SignatureAlgorithm.HS256)
                .compact();

        assertThat(jwtUtil.validateToken(foreign)).isFalse();
    }

    @Test
    @DisplayName("Un token expire est refuse")
    void expiredTokenIsInvalid() {
        JwtUtil court = new JwtUtil(SECRET, -1_000L);
        String expire = court.generateToken("admin");

        assertThat(jwtUtil.validateToken(expire)).isFalse();
    }

    @Test
    @DisplayName("Une chaine quelconque est refusee sans lever d'exception")
    void garbageTokenIsInvalid() {
        assertThat(jwtUtil.validateToken("pas-un-token")).isFalse();
    }

    @Test
    @DisplayName("L'expiration annoncee correspond a la configuration")
    void expirationComesFromConfiguration() {
        assertThat(jwtUtil.getExpirationMillis()).isEqualTo(3_600_000L);

        String token = jwtUtil.generateToken("admin");
        long delta = jwtUtil.extractExpiration(token).getTime() - System.currentTimeMillis();
        assertThat(delta).isBetween(3_500_000L, 3_600_000L);
    }
}