package tfm.unir.ing.ms_auth_tfm.service;

import org.springframework.http.ResponseEntity;
import tfm.unir.ing.ms_auth_tfm.dto.SimpleResponse;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthRequest;
import tfm.unir.ing.ms_auth_tfm.dto.login.AuthResponse;
import tfm.unir.ing.ms_auth_tfm.dto.register.RegisterRequest;
import tfm.unir.ing.ms_auth_tfm.dto.updateProfile.ProfileUpdateRequest;
import tfm.unir.ing.ms_auth_tfm.dto.userProfile.UserProfileDto;
import tfm.unir.ing.ms_auth_tfm.dto.users.UserResponse;

import java.util.List;

public interface UserServiceInterface {

    /**
     * Registra un nuevo usuario en el sistema.
     */
    ResponseEntity<SimpleResponse> registerUser(RegisterRequest request);

    /**
     * Autentica un usuario y devuelve un token JWT.
     */
    ResponseEntity<AuthResponse> login(AuthRequest request);

    /**
     * Actualiza perfil del usuario autenticado (nombre, placa, etc.).
     */
    ResponseEntity<SimpleResponse> updateProfile(String emailFromToken, ProfileUpdateRequest req);

    /**
     * Obtiene todos los usuarios registrados (solo para administradores).
     */
    ResponseEntity<List<UserResponse>> getAllUsers();

    /**
     * Devuelve el perfil del usuario autenticado.
     */
    UserProfileDto getCurrentProfile();
}
