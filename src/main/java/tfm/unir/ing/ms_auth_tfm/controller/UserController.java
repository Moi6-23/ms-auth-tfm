package tfm.unir.ing.ms_auth_tfm.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import tfm.unir.ing.ms_auth_tfm.dto.SimpleResponse;
import tfm.unir.ing.ms_auth_tfm.dto.updateProfile.ProfileUpdateRequest;
import tfm.unir.ing.ms_auth_tfm.dto.userProfile.UserProfileDto;
import tfm.unir.ing.ms_auth_tfm.service.UserService;

import java.util.List;


@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * Devuelve el perfil del usuario autenticado leyendo el principal del SecurityContext.
     * Requiere que el JwtAuthenticationFilter haya validado el token.
     */
    @GetMapping("/profiles")
    public ResponseEntity<UserProfileDto> userProfile() {
        return ResponseEntity.ok(userService.getCurrentProfile());
    }

    @PatchMapping("/profiles")
    public ResponseEntity<SimpleResponse> updateProfile(@Valid @RequestBody ProfileUpdateRequest request) {
        tfm.unir.ing.ms_auth_tfm.entity.User principal =
                (tfm.unir.ing.ms_auth_tfm.entity.User) SecurityContextHolder.getContext()
                        .getAuthentication().getPrincipal();

        String emailFromToken = principal.getEmail();
        log.info("[PATCH] Solicitud unificada perfil/contraseña para {}", emailFromToken);

        return userService.updateProfile(emailFromToken, request);
    }
}