package com.whizzy.rentcloud.authservice.repository.auth.mapper;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.whizzy.rentcloud.authservice.model.auth.Client;
import com.whizzy.rentcloud.authservice.util.OAuth2Util;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class RegisteredClientToEntityMapper {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public RegisteredClientToEntityMapper() {
        ClassLoader classLoader = RegisteredClientToEntityMapper.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    public Client toEntity(RegisteredClient registeredClient) {
        List<String> clientAuthenticationMethods = registeredClient.getClientAuthenticationMethods().stream()
                .map(c -> c.getValue()).collect(Collectors.toList());

        List<String> authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes().stream()
                .map(c -> c.getValue()).collect(Collectors.toList());

        Client entity = new Client();
        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        entity.setClientName(registeredClient.getClientName());
        entity.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
        entity.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
        entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        entity.setPostLogoutRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()));
        entity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));
        entity.setClientSettings(OAuth2Util.writeMap(this.objectMapper, registeredClient.getClientSettings().getSettings()));
        entity.setTokenSettings(OAuth2Util.writeMap(this.objectMapper, registeredClient.getTokenSettings().getSettings()));

        return entity;
    }

    public RegisteredClient toRegisteredClient(Client client) {
        Set<String> authMethods =  StringUtils.commaDelimitedListToSet(client.getClientAuthenticationMethods());
        Set<String> authGrantTypes = StringUtils.commaDelimitedListToSet(client.getAuthorizationGrantTypes());
        Set<String> redirectUris = StringUtils.commaDelimitedListToSet(client.getRedirectUris());
        Set<String> postLogoutRedirectUris = StringUtils.commaDelimitedListToSet(client.getPostLogoutRedirectUris());
        Set<String> clientScopes = StringUtils.commaDelimitedListToSet(client.getScopes());

        RegisteredClient.Builder builder = RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())
                .clientAuthenticationMethods(x -> authMethods.forEach(
                        authMethod -> x.add(OAuth2Util.resolveClientAuthenticationMethod(authMethod))
                ))
                .authorizationGrantTypes(grantTypes -> authGrantTypes.forEach(
                        grantType -> grantTypes.add(OAuth2Util.resolveAuthorizationGrantType(grantType))
                ))
                .redirectUris((uris) -> uris.addAll(redirectUris))
                .postLogoutRedirectUris((uris) -> uris.addAll(postLogoutRedirectUris))
                .scopes((scopes) -> scopes.addAll(clientScopes));

        if(StringUtils.hasText(client.getClientSettings())) {
            Map<String, Object> clientSettingsMap = OAuth2Util.parseMap(this.objectMapper, client.getClientSettings());
            builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());
        }

        if(StringUtils.hasText(client.getTokenSettings())) {
            Map<String, Object> tokenSettingsMap = OAuth2Util.parseMap(this.objectMapper, client.getTokenSettings());
            builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());
        }
        return builder.build();
    }
}
