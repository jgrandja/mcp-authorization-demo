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

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.client.RestClient;

/**
 * @author Joe Grandja
 */
public class ClientRegistrar {
	private final RestClient restClient;

	public ClientRegistrar(RestClient restClient) {
		this.restClient = restClient;
	}

	public record ClientRegistrationRequest(
			@JsonProperty("client_name") String clientName,
			@JsonProperty("grant_types") List<String> grantTypes,
			@JsonProperty("redirect_uris") List<String> redirectUris,
			@JsonProperty("resource_ids") List<String> resourceIds,
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
			@JsonProperty("resource_ids") List<String> resourceIds,
			String scope) {
	}

	public ClientRegistrationResponse registerClient(String resourceId, String registrationEndpointUri, String initialAccessToken) {
		ClientRegistrationRequest clientRegistrationRequest = new ClientRegistrationRequest(
				"mcp-client-1",
				List.of(
						AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
						AuthorizationGrantType.REFRESH_TOKEN.getValue(),
						AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()),
				List.of("http://127.0.0.1:8080/authorized"),
				List.of(resourceId),
				"message.read"
		);

		return registerClient(registrationEndpointUri, initialAccessToken, clientRegistrationRequest);
	}

	public ClientRegistrationResponse registerClient(String registrationEndpointUri, String initialAccessToken, ClientRegistrationRequest request) {
		return this.restClient
				.post()
				.uri(registrationEndpointUri)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(initialAccessToken))
				.body(request)
				.retrieve()
				.body(ClientRegistrationResponse.class);
	}

	public ClientRegistrationResponse retrieveClient(String registrationAccessToken, String registrationClientUri) {
		return this.restClient
				.get()
				.uri(registrationClientUri)
				.header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(registrationAccessToken))
				.retrieve()
				.body(ClientRegistrationResponse.class);
	}

}
