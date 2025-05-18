package tfm.unir.ing.ms_auth_tfm.dto.login;

import lombok.Data;

@Data
public class AuthRequest {
    private String username;
    private String password;
}
