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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import sample.config.ManagedClientRegistrationRepository;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

/**
 * @author Joe Grandja
 */
@Controller
public class McpAuthorizationController {
	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
			"anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private final RestClient restClient;
	private final String messagesBaseUri;
	private final OAuth2AuthorizedClientManager authorizedClientManager;
	private final ManagedClientRegistrationRepository managedClientRegistrationRepository;
	private final ClientRegistrar clientRegistrar = new ClientRegistrar(RestClient.builder().build());

	public McpAuthorizationController(
			@Qualifier("oauth2-rest-client") RestClient restClient,
			@Value("${messages.base-uri}") String messagesBaseUri,
			OAuth2AuthorizedClientManager authorizedClientManager,
			ManagedClientRegistrationRepository managedClientRegistrationRepository) {
		this.restClient = restClient;
		this.messagesBaseUri = messagesBaseUri;
		this.authorizedClientManager = authorizedClientManager;
		this.managedClientRegistrationRepository = managedClientRegistrationRepository;
	}

	@GetMapping(value = "/mcp")
	public String mcpAuthorization(@RequestParam(value="registrationId", required = false) String registrationId,
								   @RequestParam(value="resource", required = false) String resource,
								   Model model) {
		RestClient.RequestHeadersSpec<?> requestSpec = this.restClient
				.get()
				.uri(this.messagesBaseUri);
		if (StringUtils.hasText(registrationId)) {
			requestSpec.attributes(clientRegistrationId(registrationId));
		}
		String[] messages = requestSpec
				.retrieve()
				.body(String[].class);
		model.addAttribute("messages", messages);

		return "index";
	}

	@ExceptionHandler(HttpClientErrorException.Unauthorized.class)
	public String handleUnauthorized(Model model, HttpClientErrorException.Unauthorized unauthorizedException) {
		HttpHeaders responseHeaders = unauthorizedException.getResponseHeaders();
		String wwwAuthenticateHeader = responseHeaders.getFirst(HttpHeaders.WWW_AUTHENTICATE);
		Map<String, String> parameters = parseWwwAuthenticateHeader(wwwAuthenticateHeader);
		String resourceMetadataUri = parameters.get("resource_metadata");
		if (StringUtils.hasText(resourceMetadataUri)) {
			Map<String, Object> protectedResourceMetadata = this.restClient
					.get()
					.uri(resourceMetadataUri)
					.retrieve()
					.body(STRING_OBJECT_MAP);

			@SuppressWarnings("unchecked")
			String resourceId = (String) protectedResourceMetadata.get("resource");
			@SuppressWarnings("unchecked")
			List<String> authorizationServers = (List<String>) protectedResourceMetadata.get("authorization_servers");
			String authorizationServer = authorizationServers.get(0);
			Map<String, Object> authorizationServerMetadata = this.restClient
					.get()
					.uri(authorizationServer.concat("/.well-known/openid-configuration"))
					.retrieve()
					.body(STRING_OBJECT_MAP);

			@SuppressWarnings("unchecked")
			String clientRegistrationEndpoint = (String) authorizationServerMetadata.get("registration_endpoint");

			// FIXME Check to make sure client is not already registered from previous flow
			ClientRegistration clientRegistration = registerClient(resourceId, clientRegistrationEndpoint);

			return "redirect:/mcp?registrationId=" + clientRegistration.getRegistrationId() + "&resource=" + resourceId;
		}

		model.addAttribute("error", unauthorizedException.getMessage());
		return "index";
	}

	private ClientRegistration registerClient(String resourceId, String clientRegistrationEndpoint) {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("registrar-client")
				.principal(ANONYMOUS_AUTHENTICATION)
				.build();
		OAuth2AuthorizedClient authorizedRegistrarClient = this.authorizedClientManager.authorize(authorizeRequest);

		ClientRegistrar.ClientRegistrationResponse clientRegistrationResponse = this.clientRegistrar.registerClient(
				resourceId, clientRegistrationEndpoint, authorizedRegistrarClient.getAccessToken().getTokenValue());

		String registrationId = clientRegistrationResponse.clientName().concat("-").concat(UUID.randomUUID().toString());

		List<String> scopes = Arrays.asList(StringUtils.delimitedListToStringArray(clientRegistrationResponse.scope(), " "));

		ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId)
				.clientId(clientRegistrationResponse.clientId())
				.clientSecret(clientRegistrationResponse.clientSecret())
				.clientAuthenticationMethod(ClientAuthenticationMethod.valueOf(clientRegistrationResponse.tokenEndpointAuthenticationMethod()))
				.scope(scopes)
				.clientName(clientRegistrationResponse.clientName())
				.authorizationUri(authorizedRegistrarClient.getClientRegistration().getProviderDetails().getAuthorizationUri())
				.tokenUri(authorizedRegistrarClient.getClientRegistration().getProviderDetails().getTokenUri());

		clientRegistrationResponse.grantTypes().forEach((grantType) -> builder.authorizationGrantType(new AuthorizationGrantType(grantType)));

		clientRegistrationResponse.redirectUris().forEach(builder::redirectUri);

		builder.clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build());

		ClientRegistration clientRegistration = builder.build();
		this.managedClientRegistrationRepository.register(clientRegistration);

		return clientRegistration;
	}

	@ExceptionHandler(RestClientResponseException.class)
	public String handleError(Model model, RestClientResponseException ex) {
		model.addAttribute("error", ex.getMessage());
		return "index";
	}

	private static Map<String, String> parseWwwAuthenticateHeader(String wwwAuthenticateHeader) {
		if (!StringUtils.hasLength(wwwAuthenticateHeader)
				|| !StringUtils.startsWithIgnoreCase(wwwAuthenticateHeader, "bearer")) {
			return Map.of();
		}

		String headerValue = wwwAuthenticateHeader.substring("bearer".length()).stripLeading();
		Map<String, String> parameters = new HashMap<>();
		for (String kvPair : StringUtils.delimitedListToStringArray(headerValue, ",")) {
			String[] kv = StringUtils.split(kvPair, "=");
			if (kv == null || kv.length <= 1) {
				continue;
			}
			parameters.put(kv[0].trim(), kv[1].trim().replace("\"", ""));
		}

		return parameters;
	}

}
