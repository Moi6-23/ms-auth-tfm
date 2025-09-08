package tfm.unir.ing.ms_auth_tfm.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tfm.unir.ing.ms_auth_tfm.dto.userProfile.UserProfileDto;
import tfm.unir.ing.ms_auth_tfm.service.UserService;

@RestController
@RequestMapping("/api/profile")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * Devuelve el perfil del usuario autenticado leyendo el principal del SecurityContext.
     * Requiere que el JwtAuthenticationFilter haya validado el token.
     */
    @GetMapping("/me")
    public ResponseEntity<UserProfileDto> userProfile() {
        return ResponseEntity.ok(userService.getCurrentProfile());
    }
}