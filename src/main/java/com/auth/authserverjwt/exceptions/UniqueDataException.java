package com.auth.authserverjwt.exceptions;


public class UniqueDataException extends RuntimeException {
    public UniqueDataException(String message) {
        super(message);
    }
}
