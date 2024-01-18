package com.whizzy.rentcloud.authservice.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;

@JsonInclude(value = JsonInclude.Include.NON_EMPTY)
public class AuthUserDetail extends User implements UserDetails {

    @JsonProperty("authorities")
    private  Collection<GrantedAuthority> authorities;

    public AuthUserDetail() {
        super();
        this.authorities = new HashSet<>();
    }

    public AuthUserDetail(User user, Collection<GrantedAuthority> authorities) {
        super(user);
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return super.getPassword();
    }

    @Override
    public String getUsername() {
        return super.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return super.isEnabled();
    }

    public void setAuthorities(Collection<GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    public void setUsername(String username) {
        super.setUsername(username);
    }

    public void setPassword(String password) {
        super.setPassword(password);
    }

    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        super.setAccountNonExpired(accountNonExpired);
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        super.setCredentialsNonExpired(credentialsNonExpired);
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        super.setAccountNonLocked(accountNonLocked);
    }
}
