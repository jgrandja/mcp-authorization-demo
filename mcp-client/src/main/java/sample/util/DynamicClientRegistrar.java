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
package sample.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonProperty;
import sample.config.ManagedClientRegistrationRepository;

import org.springframework.http.MediaType;
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
	private final RestClient restClient = RestClient.builder().build();
	private final ManagedClientRegistrationRepository managedClientRegistrationRepository;

	public DynamicClientRegistrar(
			ManagedClientRegistrationRepository managedClientRegistrationRepository) {
		Assert.notNull(managedClientRegistrationRepository, "managedClientRegistrationRepository cannot be null");
		this.managedClientRegistrationRepository = managedClientRegistrationRepository;
	}

	public List<ClientRegistration> registerClient(
			ClientRegistrationRequest clientRegistrationRequest,
			AuthorizationServerDiscoverer.AuthorizationServerMetadata authorizationServerMetadata) {

		ClientRegistrationResponse clientRegistrationResponse = this.restClient
				.post()
				.uri(authorizationServerMetadata.registrationEndpoint())
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.body(clientRegistrationRequest)
				.retrieve()
				.body(ClientRegistrationResponse.class);

		List<ClientRegistration> clientRegistrations = new ArrayList<>();

		if (clientRegistrationResponse.grantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())) {
			clientRegistrations.add(
					registerClientAuthorizationCodeGrant(clientRegistrationResponse, authorizationServerMetadata));
		}
		if (clientRegistrationResponse.grantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())) {
			clientRegistrations.add(
					registerClientClientCredentialsGrant(clientRegistrationResponse, authorizationServerMetadata));
		}

		return clientRegistrations;
	}

	private ClientRegistration registerClientAuthorizationCodeGrant(
			ClientRegistrationResponse clientRegistrationResponse,
			AuthorizationServerDiscoverer.AuthorizationServerMetadata authorizationServerMetadata) {

		ClientRegistration.Builder builder = builder(clientRegistrationResponse, authorizationServerMetadata)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationUri(authorizationServerMetadata.authorizationEndpoint())
				.clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build());

		clientRegistrationResponse.redirectUris().forEach(builder::redirectUri);

		ClientRegistration clientRegistration = builder.build();

		this.managedClientRegistrationRepository.register(clientRegistration);

		return clientRegistration;
	}

	private ClientRegistration registerClientClientCredentialsGrant(
			ClientRegistrationResponse clientRegistrationResponse,
			AuthorizationServerDiscoverer.AuthorizationServerMetadata authorizationServerMetadata) {

		ClientRegistration clientRegistration = builder(clientRegistrationResponse, authorizationServerMetadata)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();

		this.managedClientRegistrationRepository.register(clientRegistration);

		return clientRegistration;
	}

	private ClientRegistration.Builder builder(
			ClientRegistrationResponse clientRegistrationResponse,
			AuthorizationServerDiscoverer.AuthorizationServerMetadata authorizationServerMetadata) {

		String registrationId = clientRegistrationResponse.clientName().concat("-").concat(UUID.randomUUID().toString());

		List<String> scopes = Arrays.asList(StringUtils.delimitedListToStringArray(clientRegistrationResponse.scope(), " "));

		return ClientRegistration.withRegistrationId(registrationId)
				.clientId(clientRegistrationResponse.clientId())
				.clientSecret(clientRegistrationResponse.clientSecret())
				.clientAuthenticationMethod(
						ClientAuthenticationMethod.valueOf(clientRegistrationResponse.tokenEndpointAuthenticationMethod()))
				.scope(scopes)
				.clientName(registrationId)
				.tokenUri(authorizationServerMetadata.tokenEndpoint());
	}

	public record ClientRegistrationRequest(
			@JsonProperty("client_name") String clientName,
			@JsonProperty("grant_types") List<String> grantTypes,
			@JsonProperty("redirect_uris") List<String> redirectUris,
			@JsonProperty("resource_ids") List<String> resourceIds,		// Custom metadata
			String scope) {
	}

	public record ClientRegistrationResponse(
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
