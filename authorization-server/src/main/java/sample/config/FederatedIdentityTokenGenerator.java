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

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * @author Joe Grandja
 */
public final class FederatedIdentityTokenGenerator implements OAuth2TokenGenerator<OAuth2AccessToken> {
    private final OAuth2AuthorizedClientService authorizedClientService;

    public FederatedIdentityTokenGenerator(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public OAuth2AccessToken generate(OAuth2TokenContext context) {
        if (context.getTokenType() == null || !OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return null;
        }

        Authentication principal = context.getPrincipal();
        if (!(principal instanceof OAuth2AuthenticationToken oauth2Authentication)) {
            return null;
        }

        OAuth2AuthorizedClient authorizedClient = this.authorizedClientService.loadAuthorizedClient(
                oauth2Authentication.getAuthorizedClientRegistrationId(), principal.getName());

        return (authorizedClient != null) ? authorizedClient.getAccessToken() : null;
    }

}
