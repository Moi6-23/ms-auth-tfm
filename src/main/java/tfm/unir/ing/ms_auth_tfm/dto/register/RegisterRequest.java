package tfm.unir.ing.ms_auth_tfm.dto.register;
import lombok.Data;

@Data
public class RegisterRequest {
    private String name;
    private String email;
    private String placaVehiculo;
    private String password;
}
