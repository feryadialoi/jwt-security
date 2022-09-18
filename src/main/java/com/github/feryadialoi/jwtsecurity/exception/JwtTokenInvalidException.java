package com.github.feryadialoi.jwtsecurity.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtTokenInvalidException extends AuthenticationException {
    public JwtTokenInvalidException() {
        super("jwt token invalid");
    }

    public JwtTokenInvalidException(String message) {
        super(message);
    }
}
