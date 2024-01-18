package com.whizzy.rentcloud.authservice.model.auth;

import com.whizzy.rentcloud.authservice.model.auth.compositkey.AuthorizationConsentKey;
import jakarta.persistence.*;

@Entity
@Table(name = "`authorizationConsent`")
@IdClass(AuthorizationConsentKey.class)
public class AuthorizationConsent {

    @Id
    private String registeredClientId;
    @Id
    private String principalName;
    @Column(length = 1000)
    private String authorities;

    public AuthorizationConsent() {
    }

    public String getRegisteredClientId() {
        return registeredClientId;
    }

    public void setRegisteredClientId(String registeredClientId) {
        this.registeredClientId = registeredClientId;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public String getAuthorities() {
        return authorities;
    }

    public void setAuthorities(String authorities) {
        this.authorities = authorities;
    }
}
