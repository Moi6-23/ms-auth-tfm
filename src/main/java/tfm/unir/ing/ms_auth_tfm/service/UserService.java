package tfm.unir.ing.ms_auth_tfm.service;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import tfm.unir.ing.ms_auth_tfm.config.SecurityConfig;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthRequest;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthResponse;
import tfm.unir.ing.ms_auth_tfm.dto.register.RegisterRequest;
import tfm.unir.ing.ms_auth_tfm.dto.userProfile.UserProfileDto;
import tfm.unir.ing.ms_auth_tfm.entity.User;
import tfm.unir.ing.ms_auth_tfm.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final SecurityConfig securityConfig;
    private final JwtService jwtService;

    public void registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El correo ya está registrado");
        }

        if (userRepository.findByPlacaVehiculo(request.getPlacaVehiculo()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La placa del vehículo ya está registrada");
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPlacaVehiculo(request.getPlacaVehiculo());
        user.setPassword(securityConfig.passwordEncoder().encode(request.getPassword()));
        user.setActive(true);
        userRepository.save(user);
    }

    public AuthResponse login(AuthRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Correo no registrado"));

        if (!securityConfig.passwordEncoder().matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Contraseña incorrecta");
        }

        String token = jwtService.generateToken(user);
        return new AuthResponse(200, "Login exitoso", token);
    }

    public UserProfileDto getCurrentProfile() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No autenticado");
        }

        Object principal = auth.getPrincipal();
        User user;

        if (principal instanceof User u) {
            user = u;
        } else if (principal instanceof UserDetails ud) {
            String email = ud.getUsername();
            user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        } else if (principal instanceof String s) {
            user = userRepository.findByEmail(s)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        } else {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Principal desconocido");
        }

        if (user.getActive() == null || !user.getActive()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Usuario inactivo");
        }

        return toDto(user);
    }

    private UserProfileDto toDto(User u) {
        return UserProfileDto.builder()
                .id(u.getId())
                .name(u.getName())
                .email(u.getEmail())
                .placaVehiculo(u.getPlacaVehiculo())
                .createdAt(u.getCreatedAt())
                .active(u.getActive())
                .build();
    }
}