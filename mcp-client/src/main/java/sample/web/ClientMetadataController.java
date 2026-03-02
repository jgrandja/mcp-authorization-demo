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
package sample.web;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * @author Joe Grandja
 */
@RestController
@RequestMapping("/client-metadata")
public class ClientMetadataController {

	private final ClientMetadata clientAMetadata;

	private final ClientMetadata clientBMetadata;

	public ClientMetadataController(
			ClientRegistrationRepository clientRegistrationRepository,
			@Value("${spring.ai.mcp.client.streamable-http.connections.server1.url}") String targetResource) {
		ClientRegistration clientARegistration = clientRegistrationRepository.findByRegistrationId("cimd-client-a");
		this.clientAMetadata = convert(clientARegistration, targetResource);
		ClientRegistration clientBRegistration = clientRegistrationRepository.findByRegistrationId("cimd-client-b");
		this.clientBMetadata = convert(clientBRegistration, targetResource);
	}

	@GetMapping("/client-a.json")
	public ResponseEntity<ClientMetadata> clientA() {
		return ResponseEntity.ok()
				.cacheControl(CacheControl.maxAge(1, TimeUnit.HOURS).cachePublic())
				.body(this.clientAMetadata);
	}

	@GetMapping("/client-b.json")
	public ResponseEntity<ClientMetadata> clientB() {
		return ResponseEntity.ok()
				.cacheControl(CacheControl.maxAge(1, TimeUnit.HOURS).cachePublic())
				.body(this.clientBMetadata);
	}

	private ClientMetadata convert(ClientRegistration clientRegistration, String targetResource) {
		return new ClientMetadata(
				clientRegistration.getClientId(),
				clientRegistration.getClientName(),
				List.of(clientRegistration.getAuthorizationGrantType().getValue()),
				List.of(clientRegistration.getRedirectUri()),
				clientRegistration.getClientAuthenticationMethod().getValue(),
				List.of(targetResource),
				StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
	}

	public record ClientMetadata(
			@JsonProperty("client_id") String clientId,
			@JsonProperty("client_name") String clientName,
			@JsonProperty("grant_types") List<String> grantTypes,
			@JsonProperty("redirect_uris") List<String> redirectUris,
			@JsonProperty("token_endpoint_auth_method") String tokenEndpointAuthenticationMethod,
			@JsonProperty("resource_ids") List<String> resourceIds,		// Custom metadata
			String scope) {
	}

}