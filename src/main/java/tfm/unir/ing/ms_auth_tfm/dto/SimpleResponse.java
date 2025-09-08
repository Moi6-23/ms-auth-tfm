package tfm.unir.ing.ms_auth_tfm.dto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class SimpleResponse {
    private int code;
    private String message;
}