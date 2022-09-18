package com.github.feryadialoi.jwtsecurity;


import com.github.feryadialoi.jwtsecurity.exception.JwtTokenExpiredException;
import com.github.feryadialoi.jwtsecurity.exception.JwtTokenInvalidException;
import com.github.feryadialoi.jwtsecurity.exception.JwtTokenSignatureInvalidException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.time.Clock;
import java.util.Date;


@Slf4j
@Getter
@Setter
@Component
@AllArgsConstructor
public class JwtTokenUtil {

    private Clock clock;

    private Key getSigningKey(String secret) {
        return new SecretKeySpec(secret.getBytes(), SignatureAlgorithm.HS256.getJcaName());
    }

    public String generateJwtToken(String secret, String subject, Integer ttl) {
        Key key = getSigningKey(secret);

        long nowMillis = clock.millis();
        Date now = new Date(nowMillis);

        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .signWith(key, SignatureAlgorithm.HS256);

        Date expirationTime = new Date(nowMillis + ttl * 1000);
        jwtBuilder.setExpiration(expirationTime);

        return jwtBuilder.compact();
    }

    private String doVerifyJwtToken(String secret, String jwtToken) {
        Key key = getSigningKey(secret);
        JwtParser jwtParser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        Jws<Claims> claimsJws = jwtParser.parseClaimsJws(jwtToken);
        return claimsJws.getBody().getSubject();
    }

    public String verifyJwtToken(String secret, String jwtToken) {
        try {
            return doVerifyJwtToken(secret, jwtToken);
        } catch (ExpiredJwtException jwtException) {
            throw new JwtTokenExpiredException();
        } catch (SignatureException signatureException) {
            throw new JwtTokenSignatureInvalidException();
        } catch (Exception exception) {
            log.error("verifyJwtToken exception=", exception);
            throw new JwtTokenInvalidException();
        }
    }
}
