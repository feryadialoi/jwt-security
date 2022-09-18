package com.github.feryadialoi.jwtsecurity;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "jwt-security")
public class JwtSecurityProperties {
    private String  secret;
    private Integer jwtTtl;
}
