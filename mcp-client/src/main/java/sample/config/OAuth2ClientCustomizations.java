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

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
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
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({OAuth2ClientProperties.class})
public class OAuth2ClientCustomizations {

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
                if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes servletRequestAttributes) {
                    String resource = servletRequestAttributes.getRequest().getParameter("resource");
                    if (StringUtils.hasText(resource)) {
                        // Pass the resource parameter in authorization requests
                        params.put("resource", resource);
                    }
                }
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

    @Bean
    public Consumer<DefaultOAuth2AuthorizedClientManager> authorizedClientManagerCustomizer(
            final OAuth2AuthorizedClientRepository authorizedClientRepository) {
        return (authorizedClientManager) ->
            authorizedClientManager.setAuthorizationSuccessHandler((authorizedClient, principal, attributes) -> {
                if (authorizedClient.getAccessToken().getScopes().contains("client.create")) {
                    // Client registration access tokens are scoped to `client.create` and are
                    // one-time-use only, so don't save the OAuth2AuthorizedClient to allow
                    // for multiple client registrations.
                    return;
                }
                authorizedClientRepository.saveAuthorizedClient(
                        authorizedClient,
                        principal,
                        (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                        (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));

            });
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

}