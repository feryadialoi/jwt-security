package com.github.feryadialoi.jwtsecurity;

import com.github.feryadialoi.jwtsecurity.exception.JwtTokenNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.util.Collections;
import java.util.Map;

@RequiredArgsConstructor
public class JwtSecurityWebFilter implements WebFilter {

    private static final String PREFIX_BEARER = "Bearer ";
    private static final Map<String, Boolean> WHITELIST_REQUEST = Map.of(
            "/users/login", true,
            "/users/register", true
    );

    private final JwtSecurityProperties jwtSecurityProperties;
    private final JwtTokenUtil jwtTokenUtil;
    private final ReactiveUserDetailsService reactiveUserDetailsService;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (WHITELIST_REQUEST.containsKey(path)) {
            return chain.filter(exchange);
        }

        return resolveToken(exchange.getRequest())
                .flatMap(token -> {
                    return Mono.zip(
                            verifyTokenAndGetSubject(token).flatMap(reactiveUserDetailsService::findByUsername),
                            Mono.just(token)
                    );
                })
                .flatMap(tuple -> {
                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                            tuple.getT1(), tuple.getT2(), Collections.emptyList()
                    );
                    Context context = ReactiveSecurityContextHolder.withAuthentication(authentication);
                    return chain.filter(exchange).contextWrite(context);
                });
    }

    private Mono<String> verifyTokenAndGetSubject(String token) {
        try {
            return Mono.just(jwtTokenUtil.verifyJwtToken(jwtSecurityProperties.getSecret(), token));
        } catch (AuthenticationException authenticationException) {
            return Mono.error(authenticationException);
        }
    }

    private Mono<String> resolveToken(ServerHttpRequest request) {
        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith(PREFIX_BEARER)) {
            return Mono.error(new JwtTokenNotFoundException());
        }
        String token = authorization.replace(PREFIX_BEARER, "");
        return Mono.just(token);
    }
}
