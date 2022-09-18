package com.github.feryadialoi.jwtsecurity.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtTokenSignatureInvalidException extends AuthenticationException {
    public JwtTokenSignatureInvalidException() {
        super("jwt token unauthorized");
    }

    public JwtTokenSignatureInvalidException(String message) {
        super(message);
    }
}
