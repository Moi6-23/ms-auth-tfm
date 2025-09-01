package tfm.unir.ing.ms_auth_tfm.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tfm.unir.ing.ms_auth_tfm.dto.SimpleResponse;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthRequest;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthResponse;
import tfm.unir.ing.ms_auth_tfm.dto.register.RegisterRequest;
import tfm.unir.ing.ms_auth_tfm.service.UserService;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/sessions")
    public ResponseEntity<SimpleResponse> login(@RequestBody AuthRequest request) {
        userService.login(request);
        return ResponseEntity.ok(new SimpleResponse(200, "Inicio de sesión correcto"));
    }

    @PostMapping("/users")
    public ResponseEntity<SimpleResponse> register(@RequestBody RegisterRequest request) {
        userService.registerUser(request);
        return ResponseEntity.ok(new SimpleResponse(200, "Usuario registrado correctamente"));
    }
}
