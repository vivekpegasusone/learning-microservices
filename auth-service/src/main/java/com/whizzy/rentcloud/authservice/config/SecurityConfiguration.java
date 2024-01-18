package com.whizzy.rentcloud.authservice.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.whizzy.rentcloud.authservice.service.auth.AuthorizationConsentService;
import com.whizzy.rentcloud.authservice.service.auth.AuthorizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class SecurityConfiguration {

    @Autowired
    @Qualifier("authRegisteredClientRepository")
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private AuthorizationService authorizationService;

    @Autowired
    private AuthorizationConsentService authorizationConsentService;


//    @Bean
//    @Order(1)
//    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//
//        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
//                http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
//
//        authorizationServerConfigurer
//                .registeredClientRepository(registeredClientRepository)
//                .authorizationService(authorizationService)
//                .authorizationConsentService(authorizationConsentService)
//                .authorizationServerSettings(authorizationServerSettings())
////                .tokenGenerator(tokenGenerator)
//                .clientAuthentication(clientAuthentication -> { })
//                .authorizationEndpoint(authorizationEndpoint -> { })
//                .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint -> { })
//                .deviceVerificationEndpoint(deviceVerificationEndpoint -> { })
//                .tokenEndpoint(tokenEndpoint -> { })
//                .tokenIntrospectionEndpoint(tokenIntrospectionEndpoint -> { })
//                .tokenRevocationEndpoint(tokenRevocationEndpoint -> { })
//                .authorizationServerMetadataEndpoint(authorizationServerMetadataEndpoint -> { })
//
//                // Enable OpenID Connect 1.0
//                .oidc(oidc -> oidc
//                        .providerConfigurationEndpoint(providerConfigurationEndpoint -> { })
//                        .logoutEndpoint(logoutEndpoint -> { })
//                        .userInfoEndpoint(userInfoEndpoint -> { })
//                        .clientRegistrationEndpoint(clientRegistrationEndpoint -> { })
//                );
//
//        http.exceptionHandling(
//                // Redirect to the login page when not authenticated from the authorization endpoint
//            (exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
//                    new LoginUrlAuthenticationEntryPoint("/login"),
//                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//            )
//        ).oauth2ResourceServer( // Accept access tokens for User Info and/or Client Registration
//                (resourceServer) -> resourceServer.jwt(Customizer.withDefaults()
//            )
//        );
//        return http.build();
//    }

    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .registeredClientRepository(registeredClientRepository)
                .authorizationService(authorizationService)
                .authorizationConsentService(authorizationConsentService)
                .authorizationServerSettings(authorizationServerSettings())
                .oidc(Customizer.withDefaults());
        http.exceptionHandling(
                // Redirect to the login page when not authenticated from the authorization endpoint
                (exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((request) -> request.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
        return context -> {
            OAuth2TokenClaimsSet.Builder claims = context.getClaims();
            // Customize claims

        };
    }

//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
//        return (context) -> {
//            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//                context.getClaims().claims((claims) -> {
//                    claims.put("claim-1", "value-1");
//                    claims.put("claim-2", "value-2");
//                });
//            }
//        };
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails user = User.withUsername("vivek")
//                .password("$2a$10$KILEYUqUFb.54Svww4s9d.Ic6IwHPQRGF8lSojmhBrAoKwHM8LgWS")
//                .authorities("read").build();
//        return new InMemoryUserDetailsManager(user);
//    }

//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//    }
}
