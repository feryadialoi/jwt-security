package com.github.feryadialoi.jwtsecurity;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;

@Configuration
@Import(JwtSecurityProperties.class)
public class JwtSecurityAutoConfiguration implements BeanFactoryAware {

    private BeanFactory beanFactory;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(PasswordEncoder passwordEncoder) {
        UserDetailsRepositoryReactiveAuthenticationManager authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(beanFactory.getBean(ReactiveUserDetailsService.class));
        authenticationManager.setPasswordEncoder(passwordEncoder);
        return authenticationManager;
    }

    @Bean
    public ServerHttpSecurity serverHttpSecurity() {
        return ServerHttpSecurity.http();
    }

    @Bean
    public JwtTokenUtil jwtTokenUtil() {
        return new JwtTokenUtil(Clock.systemUTC());
    }

    @Bean
    public JwtSecurityWebFilter jwtSecurityWebFilter(JwtSecurityProperties jwtSecurityProperties, JwtTokenUtil jwtTokenUtil) {
        return new JwtSecurityWebFilter(jwtSecurityProperties, jwtTokenUtil, beanFactory.getBean(ReactiveUserDetailsService.class));
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = beanFactory;
    }
}
