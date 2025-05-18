package tfm.unir.ing.ms_auth_tfm.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import tfm.unir.ing.ms_auth_tfm.entity.User;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}

