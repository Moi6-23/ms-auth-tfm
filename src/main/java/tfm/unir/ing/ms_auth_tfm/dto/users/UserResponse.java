package tfm.unir.ing.ms_auth_tfm.dto.users;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserResponse {
    private Long id;
    private String name;
    private String email;
    private String placaVehiculo;
    private boolean active;
    private String createdAt;
    private String updatedAt;

}