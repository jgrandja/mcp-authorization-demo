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
import java.util.function.Consumer;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.util.StringUtils;

import static sample.config.CustomClientMetadataConfig.configureCustomClientMetadataConverters;
import static sample.config.CustomClientMetadataConfig.getResourceIds;

/**
 * @author Joe Grandja
 */
final class AuthorizationServerCustomizations {
	private static final String RESOURCE_PARAM_NAME = "resource";

	static void configure(OAuth2AuthorizationServerConfigurer authorizationServer) {
		// @formatter:off
		authorizationServer
			.authorizationEndpoint(authorizationEndpoint ->
				authorizationEndpoint
					.consentPage("/oauth2/consent")
					.authenticationProviders(configureAuthenticationValidator())
			)
			.oidc(oidc ->
				oidc
					.clientRegistrationEndpoint(clientRegistrationEndpoint ->
						clientRegistrationEndpoint
							.authenticationProviders(configureCustomClientMetadataConverters()))
			);
		// @formatter:on
	}

	private static Consumer<List<AuthenticationProvider>> configureAuthenticationValidator() {
		// @formatter:off
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
		// @formatter:on
	}

	private static class ResourceValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

		@Override
		public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
					authenticationContext.getAuthentication();

			if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)) {
				// resource parameter is not required for OpenID Connect flow
				return;
			}

			// Get registered resource ID's
			List<String> resourceIds = getResourceIds(authenticationContext.getRegisteredClient().getClientSettings());

			String resource = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get(RESOURCE_PARAM_NAME);

			// Compare resource parameter against registered resource ID's
			if (!StringUtils.hasText(resource) || !resourceIds.contains(resource)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
				throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
			}
		}
	}

	static void withAudienceRestrictedAccessTokens(JwtEncodingContext context) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType()) &&
				context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN) &&
				!context.getAuthorizedScopes().contains(OidcScopes.OPENID)) {

			OAuth2AuthorizationRequest authorizationRequest =
					context.getAuthorization().getAttribute(OAuth2AuthorizationRequest.class.getName());
			String authorizationRequestResource = (String) authorizationRequest.getAdditionalParameters().get(RESOURCE_PARAM_NAME);

			OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = context.getAuthorizationGrant();
			String tokenRequestResource = (String) authorizationCodeAuthentication.getAdditionalParameters().get(RESOURCE_PARAM_NAME);

			// Compare resource parameter from authorization request against resource parameter from access token request
			if (!StringUtils.hasText(tokenRequestResource) || !tokenRequestResource.equals(authorizationRequestResource)) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
			}

			context.getClaims().claim(JwtClaimNames.AUD, authorizationRequestResource);
		}
	}

}