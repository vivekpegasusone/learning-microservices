package com.whizzy.rentcloud.authservice.repository.auth;

import com.whizzy.rentcloud.authservice.model.auth.AuthorizationConsent;
import com.whizzy.rentcloud.authservice.model.auth.compositkey.AuthorizationConsentKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthorizationConsentRepository extends JpaRepository<AuthorizationConsent, AuthorizationConsentKey> {
    Optional<AuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
