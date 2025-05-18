package tfm.unir.ing.ms_auth_tfm.dto.login;

import lombok.Data;

@Data
public class AuthRequest {
    private String email;
    private String password;
}
