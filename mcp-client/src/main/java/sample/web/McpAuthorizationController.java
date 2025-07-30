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

import sample.config.ManagedClientRegistrationRepository;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
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
	private final RestClient restClient;
	private final String messagesBaseUri;
	private final AuthorizationServerDiscoverer authorizationServerDiscoverer;
	private final DynamicClientRegistrar dynamicClientRegistrar;

	public McpAuthorizationController(
			@Qualifier("oauth2-rest-client") RestClient restClient,
			@Value("${messages.base-uri}") String messagesBaseUri,
			ManagedClientRegistrationRepository managedClientRegistrationRepository,
			OAuth2AuthorizedClientManager authorizedClientManager) {
		this.restClient = restClient;
		this.messagesBaseUri = messagesBaseUri;
		this.authorizationServerDiscoverer = new AuthorizationServerDiscoverer();
		this.dynamicClientRegistrar = new DynamicClientRegistrar(managedClientRegistrationRepository, authorizedClientManager);
	}

	@GetMapping(value = "/mcp")
	public String mcpAuthorization(
			@RequestParam(value="registrationId", required = false) String registrationId,
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
	public String handleUnauthorized(HttpClientErrorException.Unauthorized unauthorizedException) {
		String wwwAuthenticateHeader = unauthorizedException.getResponseHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);

		String resourceMetadataUri = AuthorizationServerDiscoverer.parseResourceMetadataUri(wwwAuthenticateHeader);

		AuthorizationServerDiscoverer.AuthorizationServerDiscoveryResponse authorizationServerDiscoveryResponse =
				this.authorizationServerDiscoverer.discover(resourceMetadataUri);

		AuthorizationServerDiscoverer.ProtectedResourceMetadata protectedResourceMetadata =
				authorizationServerDiscoveryResponse.protectedResourceMetadata();
		AuthorizationServerDiscoverer.AuthorizationServerMetadata authorizationServerMetadata =
				authorizationServerDiscoveryResponse.authorizationServerMetadata();

		// FIXME Check to make sure client is not already registered from a previous flow
		ClientRegistration clientRegistration = this.dynamicClientRegistrar.registerClient(
				protectedResourceMetadata.resource(), authorizationServerMetadata);

		return "redirect:/mcp?registrationId=" + clientRegistration.getRegistrationId() + "&resource=" + protectedResourceMetadata.resource();
	}

	@ExceptionHandler(RestClientResponseException.class)
	public String handleError(Model model, RestClientResponseException ex) {
		model.addAttribute("error", ex.getMessage());
		return "index";
	}

}
