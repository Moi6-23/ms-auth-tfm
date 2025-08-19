package tfm.unir.ing.ms_auth_tfm.dto;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SimpleResponse {
    private int code;
    private String message;
}