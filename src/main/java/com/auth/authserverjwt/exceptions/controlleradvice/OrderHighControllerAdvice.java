package com.auth.authserverjwt.exceptions.controlleradvice;

import com.auth.authserverjwt.exceptions.UniqueDataException;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.persistence.EntityNotFoundException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.HttpStatus.CONFLICT;


@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class OrderHighControllerAdvice extends ResponseEntityExceptionHandler {

    @ExceptionHandler(UniqueDataException.class)
    protected ResponseEntity<Object> handleUniqueDataException(UniqueDataException ex, WebRequest request) {
        ProblemDetail body = this.createProblemDetail(ex, BAD_REQUEST, "Unique data error", null,
                null, request);

        return new ResponseEntity<>(body, BAD_REQUEST);
    }

    @ExceptionHandler(EntityNotFoundException.class)
    protected ResponseEntity<Object> handleEntityNotFound(EntityNotFoundException ex, WebRequest request) {
        ProblemDetail body = this.createProblemDetail(ex, NOT_FOUND, "Entity not found", null,
                null, request);

        return new ResponseEntity<>(body, NOT_FOUND);
    }

    @ExceptionHandler(NoSuchElementException.class)
    protected ResponseEntity<Object> handleNoSuchElementException(NoSuchElementException ex, WebRequest request) {
        ProblemDetail body = this.createProblemDetail(ex, NOT_FOUND, "Entity not found", null,
                null, request);

        return new ResponseEntity<>(body, NOT_FOUND);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    protected ResponseEntity<Object> handleSQLException(DataIntegrityViolationException ex, WebRequest request) {
        ProblemDetail body = this.createProblemDetail(ex, CONFLICT, "Data integrity violation", null,
                null, request);

        return new ResponseEntity<>(body, CONFLICT);
    }

    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<Object> handleAccessDeniedException(AccessDeniedException ex,WebRequest request) {
        ProblemDetail body = this.createProblemDetail(ex, UNAUTHORIZED, "Unauthorized", null,
                null, request);

        return new ResponseEntity<>(body, UNAUTHORIZED);
    }

    @ExceptionHandler(ExpiredJwtException.class)
    protected ResponseEntity<Object> handleExpiredJwtException(ExpiredJwtException ex, WebRequest request) {
        ProblemDetail body = this.createProblemDetail(ex, UNAUTHORIZED, "JWT expired", null,
                null, request);

        return new ResponseEntity<>(body, UNAUTHORIZED);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {

        ProblemDetail body = this.createProblemDetail(ex, BAD_REQUEST, "Validation error", null,
                null, request);
        List<String> errors = new ArrayList<>();
        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            errors.add(fieldError.getField() + ": " + fieldError.getDefaultMessage());
        }
        body.setProperty("errors: ", errors);

        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }
}
