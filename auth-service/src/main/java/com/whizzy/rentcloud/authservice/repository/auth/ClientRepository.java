package com.whizzy.rentcloud.authservice.repository.auth;

import com.whizzy.rentcloud.authservice.model.auth.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {
    Optional<Client> findByClientId(String clientId);
}
