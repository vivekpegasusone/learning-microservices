package com.whizzy.rentcloud.authservice.repository.auth;

import com.whizzy.rentcloud.authservice.repository.auth.mapper.RegisteredClientToEntityMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component("authRegisteredClientRepository")
public class AuthRegisteredClientRepository implements RegisteredClientRepository {

    private final ClientRepository clientRepository;
    private final RegisteredClientToEntityMapper mapper = new RegisteredClientToEntityMapper();

    public AuthRegisteredClientRepository(@Autowired ClientRepository clientRepository) {
        Assert.notNull(clientRepository, "ClientRepository cannot be null");
        this.clientRepository = clientRepository;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        this.clientRepository.save(mapper.toEntity(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.clientRepository.findById(id).map(mapper::toRegisteredClient).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return this.clientRepository.findByClientId(clientId).map(mapper::toRegisteredClient).orElse(null);
    }
}
