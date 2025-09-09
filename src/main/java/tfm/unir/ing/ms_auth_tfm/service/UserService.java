package tfm.unir.ing.ms_auth_tfm.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import tfm.unir.ing.ms_auth_tfm.config.SecurityConfig;
import tfm.unir.ing.ms_auth_tfm.dto.SimpleResponse;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthRequest;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthResponse;
import tfm.unir.ing.ms_auth_tfm.dto.register.RegisterRequest;
import tfm.unir.ing.ms_auth_tfm.dto.updateProfile.ProfileUpdateRequest;
import tfm.unir.ing.ms_auth_tfm.dto.users.UserResponse;
import tfm.unir.ing.ms_auth_tfm.dto.userProfile.UserProfileDto;
import tfm.unir.ing.ms_auth_tfm.entity.User;
import tfm.unir.ing.ms_auth_tfm.repository.UserRepository;

import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserServiceInterface{

    private final UserRepository userRepository;
    private final SecurityConfig securityConfig;
    private final JwtService jwtService;

    @Override
    public ResponseEntity<SimpleResponse> registerUser(RegisterRequest request) {
        String normalizedEmail = request.getEmail().trim().toLowerCase();
        String plate = request.getPlacaVehiculo().trim().toUpperCase();
        String password   = request.getPassword() == null ? "" : request.getPassword();

        log.info("Intento de registro con email={} placa={}", normalizedEmail, plate);

        // Validar unicidad de email
        if (userRepository.findByEmailIgnoreCase(normalizedEmail).isPresent()) {
            log.warn("El correo {} ya está registrado", normalizedEmail);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "El correo ya está registrado"));
        }
        if (!password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^\\w\\s]).{8,64}$")) {
            log.warn("Política de complejidad no cumplida para {}", normalizedEmail);
            return ResponseEntity.badRequest()
                    .body(new SimpleResponse(400,
                            "La contraseña debe incluir mayúsculas, minúsculas, dígitos y un caracter especial"));
        }
        // Crear usuario
        User user = new User();
        user.setName(request.getName());
        user.setEmail(normalizedEmail);
        user.setPlacaVehiculo(plate);
        user.setPassword(securityConfig.passwordEncoder().encode(request.getPassword()));
        user.setActive(true);
        userRepository.save(user);

        log.info("Usuario registrado exitosamente con email={}", normalizedEmail);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new SimpleResponse(201, "Usuario registrado correctamente"));
    }

    @Override
    public ResponseEntity<AuthResponse> login(AuthRequest request) {
        final String normalizedEmail = request.getEmail() == null ? null : request.getEmail().trim().toLowerCase();

        log.info("Intento de login para {}", normalizedEmail);

        Optional<User> optUser = userRepository.findByEmailIgnoreCase(normalizedEmail);
        if (optUser.isEmpty()) {
            log.warn("Correo no registrado: {}", normalizedEmail);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new AuthResponse(400, "Correo no registrado", null));
        }

        User user = optUser.get();
        if (!securityConfig.passwordEncoder().matches(request.getPassword(), user.getPassword())) {
            log.warn("Contraseña incorrecta para {}", normalizedEmail);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new AuthResponse(400, "Contraseña incorrecta", null));
        }

        String token = jwtService.generateToken(user);
        log.info("Login exitoso para {}", normalizedEmail);

        return ResponseEntity.ok(new AuthResponse(200, "Login exitoso", token));
    }

    @Override
    public ResponseEntity<SimpleResponse> updateProfile(String emailFromToken, ProfileUpdateRequest req) {
        final String email = emailFromToken == null ? null : emailFromToken.trim().toLowerCase();
        if (email == null || email.isBlank()) {
            log.warn("Token sin email válido en upsert de perfil");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new SimpleResponse(401, "No autorizado"));
        }

        Optional<User> optUser = userRepository.findByEmailIgnoreCase(email);
        if (optUser.isEmpty()) {
            log.warn("Usuario no encontrado para email {}", email);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "Usuario no encontrado"));
        }
        User user = optUser.get();

        boolean touchedProfile = false;
        boolean touchedPassword = false;

        // ---------- PERFIL ----------
        if (req.getName() != null) {
            String newName = req.getName().trim().replaceAll("\\s+", " ");
            user.setName(newName);
            touchedProfile = true;
        }

        if (req.getPlacaVehiculo() != null) {
            String newPlate = req.getPlacaVehiculo().trim().toUpperCase();
            user.setPlacaVehiculo(newPlate);
            touchedProfile = true;
        }

        // ---------- CONTRASEÑA ----------
        boolean anyPasswordField =
                req.getCurrentPassword() != null ||
                        req.getNewPassword() != null ||
                        req.getConfirmNewPassword() != null;

        if (anyPasswordField) {
            String current = req.getCurrentPassword() == null ? "" : req.getCurrentPassword();
            String nueva   = req.getNewPassword() == null ? "" : req.getNewPassword();
            String confirm = req.getConfirmNewPassword() == null ? "" : req.getConfirmNewPassword();

            // Reglas existentes (las tuyas)
            if (nueva.length() < 8 || nueva.length() > 64) {
                log.warn("Política de longitud de contraseña no cumplida para {}", email);
                return ResponseEntity.badRequest()
                        .body(new SimpleResponse(400, "La nueva contraseña debe tener entre 8 y 64 caracteres"));
            }
            if (!nueva.equals(confirm)) {
                log.warn("Confirmación de contraseña no coincide para {}", email);
                return ResponseEntity.badRequest()
                        .body(new SimpleResponse(400, "La confirmación de la nueva contraseña no coincide"));
            }
            if (!securityConfig.passwordEncoder().matches(current, user.getPassword())) {
                log.warn("Contraseña actual inválida para {}", email);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new SimpleResponse(400, "La contraseña actual es incorrecta"));
            }
            if (securityConfig.passwordEncoder().matches(nueva, user.getPassword())) {
                log.warn("Nueva contraseña igual a la actual para {}", email);
                return ResponseEntity.badRequest()
                        .body(new SimpleResponse(400, "La nueva contraseña no puede ser igual a la actual"));
            }
            if (!nueva.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^\\w\\s]).{8,64}$")) {
                log.warn("Política de complejidad no cumplida para {}", email);
                return ResponseEntity.badRequest()
                        .body(new SimpleResponse(400,
                                "La contraseña debe incluir mayúsculas, minúsculas, dígitos y un caracter especial"));
            }

            String encoded = securityConfig.passwordEncoder().encode(nueva);
            user.setPassword(encoded);
            touchedPassword = true;
        }

        if (!touchedProfile && !touchedPassword) {
            log.info("Solicitud sin cambios aplicables para {}", email);
            return ResponseEntity.ok(new SimpleResponse(200, "Sin cambios"));
        }

        userRepository.save(user);

        if (touchedProfile && touchedPassword) {
            log.info("Perfil y contraseña actualizados OK: userId={}, email={}", user.getId(), email);
            return ResponseEntity.ok(new SimpleResponse(200, "Perfil y contraseña actualizados correctamente"));
        } else if (touchedProfile) {
            log.info("Perfil actualizado OK: userId={}, email={}", user.getId(), email);
            return ResponseEntity.ok(new SimpleResponse(200, "Perfil actualizado correctamente"));
        } else {
            log.info("Contraseña actualizada OK: userId={}, email={}", user.getId(), email);
            return ResponseEntity.ok(new SimpleResponse(200, "Contraseña actualizada correctamente"));
        }
    }

    @Override
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        log.info("Consultando todos los usuarios registrados");

        List<User> users = userRepository.findAll();

        if (users.isEmpty()) {
            log.warn("No hay usuarios registrados en el sistema");
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build(); // 204 No Content
        }

        DateTimeFormatter fmt = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

        List<UserResponse> response = users.stream()
                .sorted(Comparator.comparing(
                        User::getCreatedAt,
                        Comparator.nullsLast(Comparator.naturalOrder())
                ).reversed())
                .map(u -> new UserResponse(
                        u.getId(),
                        u.getName(),
                        u.getEmail(),
                        u.getPlacaVehiculo(),
                        Boolean.TRUE.equals(u.getActive()),
                        u.getCreatedAt() != null ? u.getCreatedAt().format(fmt) : null,
                        u.getUpdatedAt() != null ? u.getUpdatedAt().format(fmt) : null
                ))
                .collect(Collectors.toList());

        log.info("Usuarios recuperados: {}", response.size());
        return ResponseEntity.ok(response);
    }

    @Override
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
            user = userRepository.findByEmailIgnoreCase(email)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
        } else if (principal instanceof String s) {
            user = userRepository.findByEmailIgnoreCase(s)
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