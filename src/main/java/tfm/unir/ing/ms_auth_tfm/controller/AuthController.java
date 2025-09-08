package tfm.unir.ing.ms_auth_tfm.controller;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tfm.unir.ing.ms_auth_tfm.dto.SimpleResponse;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthRequest;
import tfm.unir.ing.ms_auth_tfm.dto.register.RegisterRequest;
import tfm.unir.ing.ms_auth_tfm.dto.users.UserResponse;
import tfm.unir.ing.ms_auth_tfm.service.UserService;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/sessions")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        userService.login(request);
        return ResponseEntity.ok(userService.login(request));
    }

    @PostMapping("/users")
    public ResponseEntity<SimpleResponse> register(@RequestBody RegisterRequest request) {
        return userService.registerUser(request);
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return userService.getAllUsers();
    }

}
