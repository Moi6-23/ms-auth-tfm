package tfm.unir.ing.ms_auth_tfm.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import tfm.unir.ing.ms_auth_tfm.dto.SimpleResponse;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthRequest;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthResponse;
import tfm.unir.ing.ms_auth_tfm.dto.register.RegisterRequest;
import tfm.unir.ing.ms_auth_tfm.dto.updateProfile.ProfileUpdateRequest;
import tfm.unir.ing.ms_auth_tfm.dto.users.ChangePasswordRequest;
import tfm.unir.ing.ms_auth_tfm.dto.users.UserResponse;
import tfm.unir.ing.ms_auth_tfm.entity.User;
import tfm.unir.ing.ms_auth_tfm.service.UserService;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/sessions")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        return userService.login(request);
    }

    @PostMapping("/users")
    public ResponseEntity<SimpleResponse> register(@RequestBody RegisterRequest request) {
        return userService.registerUser(request);
    }

    @PatchMapping("/users/profile")
    public ResponseEntity<SimpleResponse> updateProfile(@Valid @RequestBody ProfileUpdateRequest request) {
        User principal = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String emailFromToken = principal.getEmail();
        log.info("[PATCH] Solicitud de actualización de perfil para usuario {}", emailFromToken);
        return userService.updateProfile(emailFromToken, request);
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return userService.getAllUsers();
    }

    @PatchMapping("/users/password")
    public ResponseEntity<SimpleResponse> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        // Opción B: principal es la entidad User
        tfm.unir.ing.ms_auth_tfm.entity.User principal =
                (tfm.unir.ing.ms_auth_tfm.entity.User) SecurityContextHolder.getContext()
                        .getAuthentication().getPrincipal();

        String emailFromToken = principal.getEmail();
        log.info("[PATCH] Solicitud de cambio de contraseña para {}", emailFromToken);

        return userService.changePassword(emailFromToken, request);
    }
}
