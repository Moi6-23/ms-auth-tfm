package tfm.unir.ing.ms_auth_tfm.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tfm.unir.ing.ms_auth_tfm.entity.User;
import tfm.unir.ing.ms_auth_tfm.repository.UserRepository;
import tfm.unir.ing.ms_auth_tfm.service.JwtService;

import java.io.IOException;
import java.util.ArrayList;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private boolean isWhitelisted(HttpServletRequest req) {
        String p = req.getServletPath();
        if (p.startsWith("/api/sessions")) return true;
        // Permitir POST /api/users (registro)
        if (p.equals("/api/users") && "POST".equalsIgnoreCase(req.getMethod())) return true;
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // 1) Deja pasar las whitelisted y sal
        if (isWhitelisted(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2) Si NO hay Authorization en rutas protegidas => 401
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            writeUnauthorized(response, "Missing or invalid Authorization header");
            return;
        }

        final String jwt = authHeader.substring(7).trim();

        try {
            // 3) Extrae el "username" (sub/email) y valida expiración/firmado
            final String userEmail = jwtService.extractUsername(jwt); // aquí te explotaba por expirado
            if (userEmail == null || userEmail.isBlank()) {
                writeUnauthorized(response, "Invalid token");
                return;
            }

            // 4) Si no hay auth ya seteado, autentica
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                final User user = userRepository.findByEmailIgnoreCase(userEmail).orElse(null);
                if (user == null) {
                    writeUnauthorized(response, "Invalid credentials");
                    return;
                }

                if (!jwtService.isTokenValid(jwt, user)) { // internamente revisa expiración y subject
                    writeUnauthorized(response, "Token expired or invalid");
                    return;
                }

                // 5) Construye Authentication y colócalo en el contexto
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

            // 6) Continua la cadena si todo OK
            filterChain.doFilter(request, response);
        }
        catch (io.jsonwebtoken.ExpiredJwtException ex) {
            writeUnauthorized(response, "Token expired");
        }
        catch (io.jsonwebtoken.security.SignatureException ex) {
            writeUnauthorized(response, "Invalid token signature");
        }
        catch (io.jsonwebtoken.MalformedJwtException | io.jsonwebtoken.UnsupportedJwtException ex) {
            writeUnauthorized(response, "Malformed or unsupported token");
        }
        catch (IllegalArgumentException ex) {
            writeUnauthorized(response, "Invalid token");
        }
        catch (Exception ex) {
            // fallback: no reveles detalles
            writeUnauthorized(response, "Unauthorized");
        }
    }

    private void writeUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
        response.setContentType("application/json");
        response.getWriter().write("{\"code\":401,\"message\":\"" + message + "\"}");
        response.getWriter().flush();
    }

}
