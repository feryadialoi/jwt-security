package com.github.feryadialoi.jwtsecurity.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtTokenExpiredException extends AuthenticationException {
    public JwtTokenExpiredException() {
        super("jwt token expired");
    }

    public JwtTokenExpiredException(String message) {
        super(message);
    }
}
