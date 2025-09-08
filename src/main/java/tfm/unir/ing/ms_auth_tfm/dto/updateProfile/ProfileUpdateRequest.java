package tfm.unir.ing.ms_auth_tfm.dto.updateProfile;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ProfileUpdateRequest {


    @Size(min = 1, max = 60, message = "El nombre debe tener entre 1 y 60 caracteres")
    @Pattern(
            regexp = "^[A-Za-zÁÉÍÓÚáéíóúÑñ\\s-]+$",
            message = "El nombre contiene caracteres inválidos"
    )
    private String name;

    @Size(min = 1, max = 10, message = "La placa debe tener entre 1 y 10 caracteres")
    // Formatos comunes CO: ABC123, ABC12D, ABC-123
    @Pattern(
            regexp = "^[A-Za-z]{3}-?[0-9A-Za-z]{3}$",
            message = "La placa del vehículo no tiene un formato válido"
    )
    private String placaVehiculo;

    // ---- CONTRASEÑA (opcionales, pero si se envía cualquiera, se exige el trío) ----

    @Size(min = 8, max = 64, message = "La contraseña actual debe tener entre 8 y 64 caracteres")
    private String currentPassword;

    @Size(min = 8, max = 64, message = "La nueva contraseña debe tener entre 8 y 64 caracteres")
    private String newPassword;

    @Size(min = 8, max = 64, message = "La confirmación debe tener entre 8 y 64 caracteres")
    private String confirmNewPassword;
}
