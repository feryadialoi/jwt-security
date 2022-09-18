package com.github.feryadialoi.jwtsecurity;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Data
public class AbstractUserDetails implements UserDetails {
    protected Collection<? extends GrantedAuthority> authorities;
    protected String password;
    protected String username;
    protected boolean isAccountNonExpired;
    protected boolean isAccountNonLocked;
    protected boolean isCredentialsNonExpired;
    protected boolean isEnabled;
}
