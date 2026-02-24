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

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.converter.OAuth2ClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.converter.RegisteredClientOAuth2ClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * @author Joe Grandja
 */
final class ClientRegistrationCustomizations {

    private static final String CLIENT_SETTINGS_NAMESPACE = "settings.client.";

    private static final String RESOURCE_IDS_KEY = "resource_ids";
    
    static Consumer<List<AuthenticationProvider>> configureClientRegistrationConverters() {
        // @formatter:off
        return (authenticationProviders) ->
                authenticationProviders.forEach((authenticationProvider) -> {
                    if (authenticationProvider instanceof OAuth2ClientRegistrationAuthenticationProvider clientRegistrationAuthenticationProvider) {
                        clientRegistrationAuthenticationProvider.setRegisteredClientConverter(new CustomRegisteredClientConverter());
                        clientRegistrationAuthenticationProvider.setClientRegistrationConverter(new CustomClientRegistrationConverter());
                    }
                });
        // @formatter:on
    }

    static List<String> getResourceIds(ClientSettings clientSettings) {
        return clientSettings.getSetting(CLIENT_SETTINGS_NAMESPACE.concat(RESOURCE_IDS_KEY));
    }

    private static final class CustomRegisteredClientConverter
            implements Converter<OAuth2ClientRegistration, RegisteredClient> {

        private final OAuth2ClientRegistrationRegisteredClientConverter delegate =
                new OAuth2ClientRegistrationRegisteredClientConverter();

        @Override
        public RegisteredClient convert(OAuth2ClientRegistration clientRegistration) {
            RegisteredClient registeredClient = this.delegate.convert(clientRegistration);
            ClientSettings.Builder clientSettingsBuilder = ClientSettings.withSettings(
                    registeredClient.getClientSettings().getSettings());
            if (clientRegistration.getClaims().get(RESOURCE_IDS_KEY) != null) {
                clientSettingsBuilder.setting(CLIENT_SETTINGS_NAMESPACE.concat(RESOURCE_IDS_KEY),
                        clientRegistration.getClaims().get(RESOURCE_IDS_KEY));
            }
            return RegisteredClient.from(registeredClient)
                    .clientSettings(clientSettingsBuilder.build())
                    .build();
        }

    }

    private static final class CustomClientRegistrationConverter
            implements Converter<RegisteredClient, OAuth2ClientRegistration> {

        private final RegisteredClientOAuth2ClientRegistrationConverter delegate =
                new RegisteredClientOAuth2ClientRegistrationConverter();

        @Override
        public OAuth2ClientRegistration convert(RegisteredClient registeredClient) {
            OAuth2ClientRegistration clientRegistration = this.delegate.convert(registeredClient);
            Map<String, Object> claims = new HashMap<>(clientRegistration.getClaims());
            ClientSettings clientSettings = registeredClient.getClientSettings();
            if (getResourceIds(clientSettings) != null) {
                claims.put(RESOURCE_IDS_KEY, getResourceIds(clientSettings));
            }
            return OAuth2ClientRegistration.withClaims(claims).build();
        }

    }

}
