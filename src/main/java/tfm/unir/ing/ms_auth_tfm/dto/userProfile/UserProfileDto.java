package tfm.unir.ing.ms_auth_tfm.dto.userProfile;


import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserProfileDto {
    private Long id;
    private String name;
    private String email;
    private String placaVehiculo;
    private LocalDateTime createdAt;
    private Boolean active;
}