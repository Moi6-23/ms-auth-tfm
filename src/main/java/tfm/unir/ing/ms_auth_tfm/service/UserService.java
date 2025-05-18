package tfm.unir.ing.ms_auth_tfm.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import tfm.unir.ing.ms_auth_tfm.config.SecurityConfig;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthRequest;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthResponse;
import tfm.unir.ing.ms_auth_tfm.dto.register.RegisterRequest;
import tfm.unir.ing.ms_auth_tfm.entity.User;
import tfm.unir.ing.ms_auth_tfm.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final SecurityConfig securityConfig;

    public void registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("El correo ya está registrado");
        }

        if (userRepository.findByPlacaVehiculo(request.getPlacaVehiculo()).isPresent()) {
            throw new IllegalArgumentException("La placa del vehículo ya está registrada");
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
                .orElseThrow(() -> new IllegalArgumentException("Correo no registrado"));

        if (!securityConfig.passwordEncoder().matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Contraseña incorrecta");
        }

        return new AuthResponse(200, "Login exitoso", null);
    }

}