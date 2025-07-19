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

import java.util.Map;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({OAuth2ClientProperties.class})
public class OAuth2ClientCustomizations {

    @Value("${spring.ai.mcp.client.sse.connections.server1.url}")
    private String targetResource;

    @Bean
    public ManagedClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties clientProperties) {
        ManagedClientRegistrationRepository clientRegistrationRepository = new ManagedClientRegistrationRepository();
        Map<String, ClientRegistration> clientRegistrations = new OAuth2ClientPropertiesMapper(clientProperties).asClientRegistrations();
        clientRegistrations.values().forEach(clientRegistrationRepository::register);
        return clientRegistrationRepository;
    }

    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(ManagedClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
                        OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        authorizationRequestResolver.setAuthorizationRequestCustomizer((builder) ->
            builder.additionalParameters((params) -> {
                // Pass the resource parameter in authorization requests
                params.put("resource", this.targetResource);
            })
        );
        return authorizationRequestResolver;
    }

    @Bean
    public RestClientAuthorizationCodeTokenResponseClient authorizationCodeTokenResponseClient() {
        RestClientAuthorizationCodeTokenResponseClient accessTokenResponseClient =
                new RestClientAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.addParametersConverter(grantRequest -> {
            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            OAuth2AuthorizationRequest authorizationRequest = grantRequest.getAuthorizationExchange().getAuthorizationRequest();
            String resource = (String) authorizationRequest.getAdditionalParameters().get("resource");
            if (StringUtils.hasText(resource)) {
                // Pass the resource parameter in access token requests
                parameters.set("resource", resource);
            }
            return parameters;
        });
        return accessTokenResponseClient;
    }

    @Bean("oauth2-rest-client")
    public RestClient oauth2RestClient(
            OAuth2AuthorizedClientRepository authorizedClientRepository,
            OAuth2AuthorizedClientManager authorizedClientManager) {
        OAuth2ClientHttpRequestInterceptor requestInterceptor =
                new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
        OAuth2AuthorizationFailureHandler authorizationFailureHandler =
                OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(authorizedClientRepository);
        requestInterceptor.setAuthorizationFailureHandler(authorizationFailureHandler);
        return RestClient.builder()
                .requestInterceptor(requestInterceptor)
                .build();
    }

    @Bean
    public Consumer<DefaultOAuth2AuthorizedClientManager> authorizedClientManagerCustomizer(
            final OAuth2AuthorizedClientRepository authorizedClientRepository) {
        return (authorizedClientManager) ->
            authorizedClientManager.setAuthorizationSuccessHandler((authorizedClient, principal, attributes) -> {
                if (authorizedClient.getAccessToken().getScopes().contains("client.create")) {
                    // Dynamic client registration access tokens are scoped to 'client.create' and are one-time-use only,
                    // so no need to save the OAuth2AuthorizedClient since the access token is no longer valid.
                    return;
                }
                authorizedClientRepository.saveAuthorizedClient(
                        authorizedClient,
                        principal,
                        (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                        (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));

            });
    }

    static AuthorizedClientServiceOAuth2AuthorizedClientManager serviceBasedAuthorizedClientManager(
            ManagedClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService,
            final String targetResource) {

        RestClientClientCredentialsTokenResponseClient accessTokenResponseClient =
                new RestClientClientCredentialsTokenResponseClient();
        accessTokenResponseClient.addParametersConverter(grantRequest -> {
            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            // Pass the resource parameter in access token requests
            parameters.set("resource", targetResource);
            return parameters;
        });

        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials(clientCredentials ->
                        clientCredentials.accessTokenResponseClient(accessTokenResponseClient))
                .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientService);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        authorizedClientManager.setAuthorizationSuccessHandler((authorizedClient, principal, attributes) -> {
            if (authorizedClient.getAccessToken().getScopes().contains("client.create")) {
                // Dynamic client registration access tokens are scoped to 'client.create' and are one-time-use only,
                // so no need to save the OAuth2AuthorizedClient since the access token is no longer valid.
                return;
            }
            authorizedClientService.saveAuthorizedClient(authorizedClient, principal);
        });

        return authorizedClientManager;
    }

}