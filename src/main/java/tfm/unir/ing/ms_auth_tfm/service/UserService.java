package tfm.unir.ing.ms_auth_tfm.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
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
import tfm.unir.ing.ms_auth_tfm.dto.users.ChangePasswordRequest;
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
public class UserService {

    private final UserRepository userRepository;
    private final SecurityConfig securityConfig;
    private final JwtService jwtService;

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

    public ResponseEntity<SimpleResponse> updateProfile(String emailFromToken, ProfileUpdateRequest request) {
        final String email = emailFromToken == null ? null : emailFromToken.trim().toLowerCase();
        if (email == null || email.isBlank()) {
            log.warn("Token sin email válido al actualizar perfil");
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new SimpleResponse(401, "No autorizado"));
        }

        log.info("Actualización de perfil iniciada para {}", email);

        // 1) Buscar usuario por email (email inmutable)
        Optional<User> optUser = userRepository.findByEmailIgnoreCase(email);
        if (optUser.isEmpty()) {
            log.warn("Usuario no encontrado para email {}", email);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "Usuario no encontrado"));
        }
        User user = optUser.get();

        // 2) Validación del nombre
        String newName = request.getName() == null ? "" : request.getName().trim().replaceAll("\\s+", " ");
        if (newName.isEmpty()) {
            log.warn("Nombre vacío en actualización de perfil para {}", email);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "El nombre no puede estar vacío"));
        }
        if (newName.length() > 60) {
            log.warn("Nombre demasiado largo ({} chars) para {}", newName.length(), email);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "El nombre excede la longitud permitida (máx. 60)"));
        }
        // opcional: restringir caracteres válidos
        if (!newName.matches("^[A-Za-zÁÉÍÓÚáéíóúÑñ\\s-]+$")) {
            log.warn("Nombre con caracteres inválidos '{}' para {}", newName, email);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "El nombre contiene caracteres inválidos"));
        }

        // 3) Validación de la placa
        String newPlate = request.getPlacaVehiculo() == null ? "" : request.getPlacaVehiculo().trim().toUpperCase();
        if (newPlate.isEmpty()) {
            log.warn("Placa vacía en actualización de perfil para {}", email);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "La placa no puede estar vacía"));
        }
        if (newPlate.length() > 10) {
            log.warn("Placa demasiado larga ({} chars) para {}", newPlate.length(), email);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "La placa excede la longitud permitida (máx. 10)"));
        }
        // Formatos comunes CO: ABC123, ABC12D, ABC-123
        if (!newPlate.matches("^[A-Z]{3}-?[0-9A-Z]{3}$")) {
            log.warn("Formato inválido de placa '{}' para {}", newPlate, email);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "La placa del vehículo no tiene un formato válido"));
        }

        // 4) Unicidad de placa si cambió
        if (!newPlate.equalsIgnoreCase(user.getPlacaVehiculo())) {
            Optional<User> conflict = userRepository.findByPlacaVehiculo(newPlate);
            if (conflict.isPresent() && !conflict.get().getId().equals(user.getId())) {
                log.warn("Conflicto: placa '{}' ya registrada por userId={}", newPlate, conflict.get().getId());
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(new SimpleResponse(400, "La placa del vehículo ya está registrada"));
            }
        }

        // 5) Persistir cambios
        log.debug("Aplicando cambios. Antes: name='{}', placa='{}'", user.getName(), user.getPlacaVehiculo());
        user.setName(newName);
        user.setPlacaVehiculo(newPlate);
        userRepository.save(user);

        log.info("Perfil actualizado OK: userId={}, email={}, name='{}', placa='{}'",
                user.getId(), user.getEmail(), user.getName(), user.getPlacaVehiculo());

        return ResponseEntity.ok(new SimpleResponse(200, "Perfil actualizado correctamente"));
    }

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

    public ResponseEntity<SimpleResponse> changePassword(String emailFromToken, ChangePasswordRequest req) {
        final String email = emailFromToken == null ? null : emailFromToken.trim().toLowerCase();
        if (email == null || email.isBlank()) {
            log.warn("Token sin email válido en cambio de contraseña");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new SimpleResponse(401, "No autorizado"));
        }

        log.info("Iniciando cambio de contraseña para {}", email);

        Optional<User> optUser = userRepository.findByEmailIgnoreCase(email);
        if (optUser.isEmpty()) {
            log.warn("Usuario no encontrado para email {}", email);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new SimpleResponse(400, "Usuario no encontrado"));
        }
        User user = optUser.get();

        // 1) Validaciones de request
        String current = req.getCurrentPassword() == null ? "" : req.getCurrentPassword();
        String nueva = req.getNewPassword() == null ? "" : req.getNewPassword();
        String confirm = req.getConfirmNewPassword() == null ? "" : req.getConfirmNewPassword();

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

        // 2) Política de complejidad (opcional pero recomendado)
        // Requiere al menos: 1 mayúscula, 1 minúscula, 1 dígito, 1 caracter especial
        if (!nueva.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^\\w\\s]).{8,64}$")) {
            log.warn("Política de complejidad no cumplida para {}", email);
            return ResponseEntity.badRequest()
                    .body(new SimpleResponse(400,
                            "La contraseña debe incluir mayúsculas, minúsculas, dígitos y un caracter especial"));
        }

        // 3) Persistir
        String encoded = securityConfig.passwordEncoder().encode(nueva);
        user.setPassword(encoded);
        userRepository.save(user);

        log.info("Contraseña actualizada correctamente para userId={} email={}", user.getId(), email);

        // Opcional: podrías invalidar/rotar tokens emitidos anteriormente (lista de deny/JTI).
        return ResponseEntity.ok(new SimpleResponse(200, "Contraseña actualizada correctamente"));
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