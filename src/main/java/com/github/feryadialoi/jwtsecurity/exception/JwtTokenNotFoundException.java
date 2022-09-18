package com.github.feryadialoi.jwtsecurity.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtTokenNotFoundException extends AuthenticationException {
    public JwtTokenNotFoundException() {
        super("jwt token not found");
    }

    public JwtTokenNotFoundException(String message) {
        super(message);
    }
}
