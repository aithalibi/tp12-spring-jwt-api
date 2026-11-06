package ma.ens.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ma.ens.security.jwt.JwtUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtUtil jwtUtil;

    private String login(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        return node.get("token").asText();
    }

    @Test
    @DisplayName("POST /api/auth/login renvoie un token pour admin")
    void loginReturnsTokenForAdmin() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"1234\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.type").value("Bearer"))
                .andExpect(jsonPath("$.roles").isArray());
    }

    @Test
    @DisplayName("POST /api/auth/login refuse un mauvais mot de passe (401)")
    void loginRejectsWrongPassword() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"0000\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Identifiants invalides"));
    }

    @Test
    @DisplayName("POST /api/auth/login refuse un utilisateur inconnu (401)")
    void loginRejectsUnknownUser() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"fantome\",\"password\":\"1234\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Le token genere permet d'appeler /api/user/profile")
    void tokenGrantsAccessToUserProfile() throws Exception {
        String token = login("user", "1111");

        mockMvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("user"))
                .andExpect(jsonPath("$.authorities[0]").value("ROLE_USER"));
    }

    @Test
    @DisplayName("Sans token, /api/user/profile renvoie 401")
    void userProfileRequiresToken() throws Exception {
        mockMvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Un token invalide est traite comme anonyme (401)")
    void invalidTokenIsAnonymous() throws Exception {
        mockMvc.perform(get("/api/user/profile").header("Authorization", "Bearer pas-un-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Un USER est refuse sur /api/admin/dashboard (403)")
    void userIsForbiddenOnAdminEndpoint() throws Exception {
        String token = login("user", "1111");

        mockMvc.perform(get("/api/admin/dashboard").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Un ADMIN accede a /api/admin/dashboard")
    void adminReachesAdminEndpoint() throws Exception {
        String token = login("admin", "1234");

        mockMvc.perform(get("/api/admin/dashboard").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.authorities").isArray());
    }

    @Test
    @DisplayName("Un ADMIN accede aussi a /api/user/profile")
    void adminReachesUserEndpoint() throws Exception {
        String token = login("admin", "1234");

        mockMvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("L'endpoint public est accessible sans token")
    void publicEndpointIsOpen() throws Exception {
        mockMvc.perform(get("/api/public/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.application").value("spring-jwt-api"));
    }

    @Test
    @DisplayName("Aucune session n'est creee : le mode est stateless")
    void noSessionIsCreated() throws Exception {
        String token = login("user", "1111");

        MvcResult result = mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNull();
    }

    @Test
    @DisplayName("Le token est accepte sans prefixe Bearer ? Non : 401")
    void tokenWithoutBearerPrefixIsRejected() throws Exception {
        String token = login("user", "1111");

        mockMvc.perform(get("/api/user/profile").header("Authorization", token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Le token contient bien le username dans son subject")
    void tokenSubjectIsUsername() throws Exception {
        String token = login("admin", "1234");

        assertThat(jwtUtil.extractUsername(token)).isEqualTo("admin");
        assertThat(jwtUtil.validateToken(token)).isTrue();
    }
}