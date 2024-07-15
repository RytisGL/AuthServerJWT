package com.auth.authserverjwt.exceptions.controlleradvice;

import org.springframework.core.annotation.Order;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;


@Order
@ControllerAdvice
public class OrderLowControllerAdvice extends ResponseEntityExceptionHandler {

    @ExceptionHandler(Exception.class)
    protected ResponseEntity<Object> handleUnspecifiedException(Exception ex, WebRequest request) {
        ProblemDetail body = this.createProblemDetail(ex, INTERNAL_SERVER_ERROR, "Internal server error", null,
                null, request);
        System.out.println(ex);
        return new ResponseEntity<>(body, INTERNAL_SERVER_ERROR);
    }
}