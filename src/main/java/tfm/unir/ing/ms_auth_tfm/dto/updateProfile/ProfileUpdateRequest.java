package tfm.unir.ing.ms_auth_tfm.dto.updateProfile;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ProfileUpdateRequest {

    @NotBlank(message = "El nombre no puede estar vacío")
    @Size(max = 60, message = "El nombre no puede superar los 60 caracteres")
    // Solo letras, espacios, guiones y tildes comunes
    @Pattern(regexp = "^[A-Za-zÁÉÍÓÚáéíóúÑñ\\s-]+$",
            message = "El nombre contiene caracteres inválidos")
    private String name;

    @NotBlank(message = "La placa del vehículo no puede estar vacía")
    @Size(max = 10, message = "La placa no puede superar los 10 caracteres")
    private String placaVehiculo;
}
