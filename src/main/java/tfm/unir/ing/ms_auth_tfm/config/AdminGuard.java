package tfm.unir.ing.ms_auth_tfm.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import tfm.unir.ing.ms_auth_tfm.service.JwtService;

@Component("adminGuard")
@RequiredArgsConstructor
public class AdminGuard {

    private final JwtService jwtService;

    @Value("${simulator.allowed-email}")
    private String allowedEmail;

    @Value("${simulator.secret-header-name}")
    private String secretHeaderName;

    @Value("${simulator.secret-header-value}")
    private String secretHeaderValue;

    public void enforce(HttpServletRequest req) {
        // 1) Tomar token del header Authorization
        String token = resolveBearerToken(req);
        if (token == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Missing or invalid Authorization header");
        }

        // 2) Extraer email/subject del JWT usando tu JwtService
        String email;
        try {
            email = jwtService.extractUsername(token); // usa el sub (setSubject(user.getEmail()))
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid token");
        }

        if (email == null || !email.equalsIgnoreCase(allowedEmail)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin email required");
        }

        // 3) Validar cabecera secreta
        if (isBlank(secretHeaderName) || isBlank(secretHeaderValue)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin header not configured");
        }

        String got = req.getHeader(secretHeaderName);
        if (got == null || !got.equals(secretHeaderValue)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid admin secret");
        }
    }

    // ---- Helpers ----
    private static String resolveBearerToken(HttpServletRequest req) {
        String auth = req.getHeader("Authorization");
        if (auth == null) return null;
        auth = auth.trim();
        if (auth.regionMatches(true, 0, "Bearer ", 0, 7) && auth.length() > 7) {
            return auth.substring(7).trim();
        }
        return null;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
