/*
 * Copyright 2020-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import sample.jose.Jwks;

import java.util.UUID;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.oauth2AuthorizationServer((authorizationServer) -> {
				http.securityMatcher(authorizationServer.getEndpointsMatcher());
				AuthorizationServerCustomizations.configure(authorizationServer);
			})
			.authorizeHttpRequests((authorize) ->
				authorize
					.requestMatchers("/oauth2/register").permitAll()	// Allow for open registration
					.anyRequest().authenticated()
			)
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			);
		// @formatter:on
		return http.build();
	}

	// @formatter:off
	@Bean("default-registeredClientRepository")
	public RegisteredClientRepository defaultRegisteredClientRepository() {
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("oidc-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
				.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();

		return new InMemoryRegisteredClientRepository(oidcClient);
	}
	// @formatter:on

	// @formatter:off
	@Bean("cimd-registeredClientRepository")
	public RegisteredClientRepository cimdRegisteredClientRepository() {
		ClientIdMetadataDocumentRegisteredClientRepository registeredClientRepository = new ClientIdMetadataDocumentRegisteredClientRepository();
		registeredClientRepository.setRegisteredClientConverter(new ClientRegistrationCustomizations.CustomRegisteredClientConverter());
		ClientIdMetadataDocumentRegisteredClientRepository.DefaultClientIdMetadataDocumentResolver metadataDocumentResolver =
				new ClientIdMetadataDocumentRegisteredClientRepository.DefaultClientIdMetadataDocumentResolver();
		metadataDocumentResolver.setAllowHttpUrlForClientIdentifier(true);
		metadataDocumentResolver.setAllowLoopbackHostForClientIdentifier(true);
		registeredClientRepository.setMetadataDocumentResolver(metadataDocumentResolver);
		return registeredClientRepository;
	}
	// @formatter:on

	// @formatter:off
	@Primary
	@Bean
	public RegisteredClientRepository registeredClientRepository(
			@Qualifier("default-registeredClientRepository") RegisteredClientRepository defaultRegisteredClientRepository,
			@Qualifier("cimd-registeredClientRepository") RegisteredClientRepository cimdRegisteredClientRepository) {
		return new RegisteredClientRepository() {

			@Override
			public void save(RegisteredClient registeredClient) {
				defaultRegisteredClientRepository.save(registeredClient);
			}

			@Override
			public @Nullable RegisteredClient findById(String id) {
				RegisteredClient registeredClient = defaultRegisteredClientRepository.findById(id);
				if (registeredClient != null) {
					return registeredClient;
				}
				return cimdRegisteredClientRepository.findById(id);
			}

			@Override
			public @Nullable RegisteredClient findByClientId(String clientId) {
				RegisteredClient registeredClient = defaultRegisteredClientRepository.findByClientId(clientId);
				if (registeredClient != null) {
					return registeredClient;
				}
				return cimdRegisteredClientRepository.findByClientId(clientId);
			}

		};
	}
	// @formatter:on

	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService() {
		return new InMemoryOAuth2AuthorizationConsentService();
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
		return AuthorizationServerCustomizations::withAudienceRestrictedAccessTokens;
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

}
