/*
 * Copyright 2020-2025 the original author or authors.
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

import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import sample.jose.Jwks;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.StringUtils;

import static org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.authorizationServer;
import static sample.config.CustomClientMetadataConfig.configureCustomClientMetadataConverters;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
	private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = authorizationServer();

		// @formatter:off
		http
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, (authorizationServer) ->
				authorizationServer
					.authorizationEndpoint(authorizationEndpoint ->
						authorizationEndpoint
							.consentPage(CUSTOM_CONSENT_PAGE_URI)
							.authenticationProviders(configureAuthenticationValidator())
					)
					.oidc(oidc ->
						oidc
							.clientRegistrationEndpoint(clientRegistrationEndpoint ->
								clientRegistrationEndpoint.authenticationProviders(configureCustomClientMetadataConverters()))
					)
			)
			.authorizeHttpRequests((authorize) ->
				authorize.anyRequest().authenticated()
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

	private Consumer<List<AuthenticationProvider>> configureAuthenticationValidator() {
		return (authenticationProviders) ->
				authenticationProviders.forEach((authenticationProvider) -> {
					if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider authorizationCodeRequestAuthenticationProvider) {
						Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
								OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.andThen(
										OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR).andThen(
												new ResourceValidator());
						authorizationCodeRequestAuthenticationProvider.setAuthenticationValidator(authenticationValidator);
					}
				});
	}

	static class ResourceValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

		@Override
		public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
					authenticationContext.getAuthentication();

			if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)) {
				// Not required for OpenID Connect
				return;
			}

			RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
			List<String> resourceIds = registeredClient.getClientSettings().getSetting("resource_ids");
			String resource = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get("resource");

			if (!StringUtils.hasText(resource) || !resourceIds.contains(resource)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
				throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
			}
		}
	}

	// @formatter:off
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("message.read")
				.scope("message.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();

		RegisteredClient registrarClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("registrar-client")
				.clientSecret("{noop}secret2")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("client.create")
				.scope("client.read")
				.build();

		return new InMemoryRegisteredClientRepository(messagingClient, registrarClient);
	}
	// @formatter:on

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
		return context -> {
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType()) &&
					context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN) &&
					!context.getAuthorizedScopes().contains(OidcScopes.OPENID)) {

				OAuth2AuthorizationRequest authorizationRequest =
						context.getAuthorization().getAttribute(OAuth2AuthorizationRequest.class.getName());
				String requestedResource = (String) authorizationRequest.getAdditionalParameters().get("resource");

				OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = context.getAuthorizationGrant();
				String resource = (String) authorizationCodeAuthentication.getAdditionalParameters().get("resource");

				if (!resource.equals(requestedResource)) {
					throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
				}

				context.getClaims().claim(JwtClaimNames.AUD, resource);
			}
		};
	}

	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService() {
		return new InMemoryOAuth2AuthorizationConsentService();
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
