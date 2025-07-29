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
package sample.web;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonProperty;
import sample.config.ManagedClientRegistrationRepository;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

/**
 * @author Joe Grandja
 */
public final class DynamicClientRegistrar {
	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
			"anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private final RestClient restClient = RestClient.builder().build();
	private final ManagedClientRegistrationRepository managedClientRegistrationRepository;
	private final OAuth2AuthorizedClientManager authorizedClientManager;

	public DynamicClientRegistrar(
			ManagedClientRegistrationRepository managedClientRegistrationRepository,
			OAuth2AuthorizedClientManager authorizedClientManager) {
		Assert.notNull(managedClientRegistrationRepository, "managedClientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		this.managedClientRegistrationRepository = managedClientRegistrationRepository;
		this.authorizedClientManager = authorizedClientManager;
	}

	public ClientRegistration registerClient(
			AuthorizationServerDiscoverer.ProtectedResourceMetadata protectedResourceMetadata,
			AuthorizationServerDiscoverer.AuthorizationServerMetadata authorizationServerMetadata) {

		ClientRegistrationRequest clientRegistrationRequest = new ClientRegistrationRequest(
				"mcp-client",
				List.of(
						AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
						AuthorizationGrantType.REFRESH_TOKEN.getValue(),
						AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()),
				List.of("http://127.0.0.1:8080/authorized"),
				List.of(protectedResourceMetadata.resource()),
				"message.read"
		);

		String registrationAccessToken = obtainRegistrationAccessToken();

		ClientRegistrationResponse clientRegistrationResponse = this.restClient
				.post()
				.uri(authorizationServerMetadata.registrationEndpoint())
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(registrationAccessToken))
				.body(clientRegistrationRequest)
				.retrieve()
				.body(ClientRegistrationResponse.class);

		String registrationId = clientRegistrationResponse.clientName().concat("-").concat(UUID.randomUUID().toString());

		List<String> scopes = Arrays.asList(StringUtils.delimitedListToStringArray(clientRegistrationResponse.scope(), " "));

		ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId)
				.clientId(clientRegistrationResponse.clientId())
				.clientSecret(clientRegistrationResponse.clientSecret())
				.clientAuthenticationMethod(ClientAuthenticationMethod.valueOf(clientRegistrationResponse.tokenEndpointAuthenticationMethod()))
				.scope(scopes)
				.clientName(clientRegistrationResponse.clientName())
				.authorizationUri(authorizationServerMetadata.authorizationEndpoint())
				.tokenUri(authorizationServerMetadata.tokenEndpoint());

		clientRegistrationResponse.grantTypes().forEach((grantType) ->
				builder.authorizationGrantType(new AuthorizationGrantType(grantType)));

		clientRegistrationResponse.redirectUris().forEach(builder::redirectUri);

		builder.clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build());

		ClientRegistration clientRegistration = builder.build();
		this.managedClientRegistrationRepository.register(clientRegistration);

		return clientRegistration;
	}

	private String obtainRegistrationAccessToken() {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("registrar-client")
				.principal(ANONYMOUS_AUTHENTICATION)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		return authorizedClient.getAccessToken().getTokenValue();
	}

	record ClientRegistrationRequest(
			@JsonProperty("client_name") String clientName,
			@JsonProperty("grant_types") List<String> grantTypes,
			@JsonProperty("redirect_uris") List<String> redirectUris,
			@JsonProperty("resource_ids") List<String> resourceIds,		// Custom metadata
			String scope) {
	}

	record ClientRegistrationResponse(
			@JsonProperty("registration_access_token") String registrationAccessToken,
			@JsonProperty("registration_client_uri") String registrationClientUri,
			@JsonProperty("client_name") String clientName,
			@JsonProperty("client_id") String clientId,
			@JsonProperty("client_secret") String clientSecret,
			@JsonProperty("token_endpoint_auth_method") String tokenEndpointAuthenticationMethod,
			@JsonProperty("grant_types") List<String> grantTypes,
			@JsonProperty("redirect_uris") List<String> redirectUris,
			@JsonProperty("resource_ids") List<String> resourceIds,		// Custom metadata
			String scope) {
	}

}
