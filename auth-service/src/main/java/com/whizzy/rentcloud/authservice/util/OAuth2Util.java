package com.whizzy.rentcloud.authservice.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class OAuth2Util {

    public  static void main(String[] args) {

        ClassLoader classLoader = OAuth2AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.registerModules(new CoreJackson2Module());

        String data = "{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"java.security.Principal\":{\"@class\":\"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\",\"authorities\":[\"java.util.Collections$UnmodifiableRandomAccessList\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_admin\"},{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"create_profile\"},{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"read_profile\"},{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"update_profile\"},{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"delete_profile\"}]],\"details\":{\"@class\":\"org.springframework.security.web.authentication.WebAuthenticationDetails\",\"remoteAddress\":\"0:0:0:0:0:0:0:1\",\"sessionId\":\"0AA068A007D6C13870C325B088DBB1B7\"},\"authenticated\":true,\"principal\":{\"@class\":\"com.whizzy.rentcloud.authserver.model.AuthUserDetail\",\"id\":null,\"username\":\"amit\",\"password\":\"$2a$10$Oa8gX0JgYCpM.m8mNJp4FOsgc7/sURGyV51lOd6hP2X72PQn3mBgG\",\"email\":\"a@gmail.com\",\"enabled\":true,\"accountNonExpired\":true,\"credentialsNonExpired\":true,\"accountNonLocked\":true,\"roles\":[\"org.hibernate.collection.spi.PersistentBag\",[{\"@class\":\"com.whizzy.rentcloud.authserver.model.Role\",\"id\":1,\"name\":\"ROLE_admin\",\"permissions\":[\"org.hibernate.collection.spi.PersistentBag\",[{\"@class\":\"com.whizzy.rentcloud.authserver.model.Permission\",\"id\":1,\"name\":\"create_profile\"},{\"@class\":\"com.whizzy.rentcloud.authserver.model.Permission\",\"id\":2,\"name\":\"read_profile\"},{\"@class\":\"com.whizzy.rentcloud.authserver.model.Permission\",\"id\":3,\"name\":\"update_profile\"},{\"@class\":\"com.whizzy.rentcloud.authserver.model.Permission\",\"id\":4,\"name\":\"delete_profile\"}]]}]],\"authorities\":[\"java.util.ArrayList\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_admin\"},{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"create_profile\"},{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"read_profile\"},{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"update_profile\"},{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"delete_profile\"}]]},\"credentials\":null},\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\":{\"@class\":\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\",\"authorizationUri\":\"http://localhost:9191/oauth2/authorize\",\"authorizationGrantType\":{\"value\":\"authorization_code\"},\"responseType\":{\"value\":\"code\"},\"clientId\":\"drishti\",\"redirectUri\":\"http://localhost:8080/code\",\"scopes\":[\"java.util.Collections$UnmodifiableSet\",[\"openid\"]],\"state\":\"Test_postman\",\"additionalParameters\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"continue\":\"\"},\"authorizationRequestUri\":\"http://localhost:9191/oauth2/authorize?response_type=code&client_id=drishti&scope=openid&state=Test_postman&redirect_uri=http://localhost:8080/code&continue=\",\"attributes\":{\"@class\":\"java.util.Collections$UnmodifiableMap\"}}}";

        //System.out.println(parseMap(objectMapper, data));

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-a")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope("scope-a")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().reuseRefreshTokens(true).build())
                .build();

        System.out.println(writeMap(objectMapper, registeredClient.getClientSettings().getSettings()));

    }

    public static String writeMap(ObjectMapper objectMpper, Map<String, Object> map) {
        try {
            return objectMpper.writeValueAsString(map);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    public static Map<String, Object> parseMap(ObjectMapper objectMapper, String data) {
        if(StringUtils.hasText(data)) {
            try {
                return objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
            } catch (Exception ex) {
                throw new IllegalArgumentException(ex.getMessage(), ex);
            }
        } else {
            return Collections.emptyMap();
        }
    }

    public static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        } else if (AuthorizationGrantType.DEVICE_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.DEVICE_CODE;
        }
        return new AuthorizationGrantType(authorizationGrantType);              // Custom authorization grant type
    }

    public static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);
    }
}
