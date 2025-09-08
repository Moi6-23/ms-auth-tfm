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
        final String jwt;

        if (isWhitelisted(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        String userEmail = jwtService.extractUsername(jwt);
        System.out.println("subject token: " + userEmail);

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            User user = userRepository.findByEmailIgnoreCase(userEmail).orElse(null);

            if (user != null && jwtService.isTokenValid(jwt, user)) {
                System.out.println("Token válido para: " + user.getEmail());
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
