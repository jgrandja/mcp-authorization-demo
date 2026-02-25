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

import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.common.McpTransportContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import sample.util.AuthorizationServerDiscoverer;
import sample.util.DynamicClientRegistrar;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.ArrayList;
import java.util.List;

import static sample.config.OAuth2ClientCustomizations.serviceBasedAuthorizedClientManager;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
public class McpClientCustomizations {

    @Value("${spring.ai.mcp.client.streamable-http.connections.server1.url}")
    private String targetResource;

    @Bean
    public McpSyncHttpClientRequestCustomizer mcpSyncHttpClientRequestCustomizer(
            ManagedClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService,
            OAuth2AuthorizedClientManager authorizedClientManager) {

        AuthorizedClientServiceOAuth2AuthorizedClientManager serviceBasedAuthorizedClientManager =
                serviceBasedAuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientService, this.targetResource);

        return new OAuth2AccessTokenRequestCustomizer(
                clientRegistrationRepository,
                authorizedClientManager,
                serviceBasedAuthorizedClientManager);
    }

    private static final class OAuth2AccessTokenRequestCustomizer implements McpSyncHttpClientRequestCustomizer {
        private final OAuth2AuthorizedClientManager defaultAuthorizedClientManager;
        private final AuthorizedClientServiceOAuth2AuthorizedClientManager serviceBasedAuthorizedClientManager;
        private final AuthorizationServerDiscoverer authorizationServerDiscoverer;
        private final DynamicClientRegistrar dynamicClientRegistrar;
        private final RestClient restClient = RestClient.builder().build();
        private ClientRegistration serviceBasedClientRegistration;
        private ClientRegistration withUserClientRegistration;

        private OAuth2AccessTokenRequestCustomizer(
                ManagedClientRegistrationRepository clientRegistrationRepository,
                OAuth2AuthorizedClientManager defaultAuthorizedClientManager,
                AuthorizedClientServiceOAuth2AuthorizedClientManager serviceBasedAuthorizedClientManager) {
            this.defaultAuthorizedClientManager = defaultAuthorizedClientManager;
            this.serviceBasedAuthorizedClientManager = serviceBasedAuthorizedClientManager;
            this.authorizationServerDiscoverer = new AuthorizationServerDiscoverer();
            this.dynamicClientRegistrar = new DynamicClientRegistrar(clientRegistrationRepository);
        }

        public void customize(HttpRequest.Builder builder, String method, URI endpoint, String body, McpTransportContext context) {
            if (this.serviceBasedClientRegistration == null || this.withUserClientRegistration == null) {
                initClientRegistrations(endpoint);
            }
            builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + getAccessToken().getTokenValue());
        }

        private OAuth2AccessToken getAccessToken() {
            if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes)) {
                // Use service-to-service OAuth2 Client when operating outside of a HttpServletRequest
                OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.serviceBasedClientRegistration.getRegistrationId())
                        .principal(this.serviceBasedClientRegistration.getClientName())
                        .build();
                return this.serviceBasedAuthorizedClientManager.authorize(authorizeRequest).getAccessToken();
            } else {
                OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.withUserClientRegistration.getRegistrationId())
                        .principal(SecurityContextHolder.getContext().getAuthentication())
                        .build();
                return this.defaultAuthorizedClientManager.authorize(authorizeRequest).getAccessToken();
            }
        }

        private void initClientRegistrations(URI mcpServerEndpoint) {
            DynamicClientRegistrar.ClientRegistrationRequest clientRegistrationRequest =
                    new DynamicClientRegistrar.ClientRegistrationRequest(
                            "mcp-client",
                            List.of(
                                    AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
                                    AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()),
                            List.of("http://127.0.0.1:8080/authorized"),
                            new ArrayList<>(),
                            "weather.read"
                    );

            List<ClientRegistration> clientRegistrations = registerClient(clientRegistrationRequest, mcpServerEndpoint);

            for (ClientRegistration registration : clientRegistrations) {
                if (registration.getAuthorizationGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                    this.withUserClientRegistration = registration;
                } else if (registration.getAuthorizationGrantType().equals(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
                    this.serviceBasedClientRegistration = registration;
                }
            }
        }

        private List<ClientRegistration> registerClient(
                DynamicClientRegistrar.ClientRegistrationRequest clientRegistrationRequest,
                URI mcpServerEndpoint) {

            List<ClientRegistration> clientRegistrations = new ArrayList<>();

            this.restClient.get()
                    .uri(mcpServerEndpoint)
                    .retrieve()
                    .onStatus(HttpStatusCode::is4xxClientError, (request, response) -> {
                        String wwwAuthenticateHeader = response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);

                        String resourceMetadataUri = AuthorizationServerDiscoverer.parseResourceMetadataUri(wwwAuthenticateHeader);

                        AuthorizationServerDiscoverer.AuthorizationServerDiscoveryResponse authorizationServerDiscoveryResponse =
                                this.authorizationServerDiscoverer.discover(resourceMetadataUri);

                        AuthorizationServerDiscoverer.ProtectedResourceMetadata protectedResourceMetadata =
                                authorizationServerDiscoveryResponse.protectedResourceMetadata();
                        AuthorizationServerDiscoverer.AuthorizationServerMetadata authorizationServerMetadata =
                                authorizationServerDiscoveryResponse.authorizationServerMetadata();

                        // Register custom metadata resource_ids
                        clientRegistrationRequest.resourceIds().add(protectedResourceMetadata.resource());

                        clientRegistrations.addAll(
                                this.dynamicClientRegistrar.registerClient(
                                        clientRegistrationRequest, authorizationServerMetadata));
                    })
                    .body(String.class);

            return clientRegistrations;
        }

    }

}