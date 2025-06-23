package tfm.unir.ing.ms_auth_tfm.dto.login;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
    private int codigo;
    private String message;
    private String token;
}