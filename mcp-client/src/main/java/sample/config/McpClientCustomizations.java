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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
public class McpClientCustomizations {

    @Bean
    public McpSyncHttpClientRequestCustomizer mcpSyncHttpClientRequestCustomizer(
            ManagedClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientManager authorizedClientManager) {

        final ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("cimd-client-b");

        return (builder, method, endpoint, body, context) -> {
            if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes) {
                OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistration.getRegistrationId())
                        .principal(SecurityContextHolder.getContext().getAuthentication())
                        .build();
                OAuth2AccessToken accessToken = authorizedClientManager.authorize(authorizeRequest).getAccessToken();
                if (accessToken != null) {
                    builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue());
                }
            }
        };
    }

}