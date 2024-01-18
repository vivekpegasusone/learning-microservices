package com.whizzy.rentcloud.authservice.model.auth.compositkey;

import java.io.Serializable;
import java.util.Objects;

public class AuthorizationConsentKey implements Serializable {
    private String principalName;
    private String registeredClientId;

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationConsentKey that = (AuthorizationConsentKey) o;
        return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(registeredClientId, principalName);
    }
}
