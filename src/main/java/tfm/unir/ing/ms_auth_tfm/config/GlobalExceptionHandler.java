package tfm.unir.ing.ms_auth_tfm.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import tfm.unir.ing.ms_auth_tfm.dto.SimpleResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<SimpleResponse> handleResponseStatus(ResponseStatusException ex) {
        return ResponseEntity
                .status(ex.getStatusCode().value())
                .body(new SimpleResponse(ex.getStatusCode().value(), ex.getReason()));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<SimpleResponse> handleRuntime(RuntimeException ex) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .body(new SimpleResponse(500, "Error interno"));
    }

}
